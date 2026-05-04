/// @file settings_routes.cpp
/// Settings page HTMX routes, fragment renderers, and YAML helpers.
/// Extracted from server.cpp — Phase 1 of the god-object decomposition.

#include "settings_routes.hpp"

#include "http_route_sink.hpp"
#include "mcp_policy.hpp"
#include "plugin_signing_helpers.hpp"
#include "web_utils.hpp"
#include <yuzu/server/server.hpp>
#include <yuzu/server/auth_db.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// httplib compat: v0.18+ moved file upload helpers to req.form (MultipartFormData).
#if __has_include(<httplib.h>)
  namespace yuzu::settings_detail {
    template<typename T, typename = void>
    struct has_form_member : std::false_type {};
    template<typename T>
    struct has_form_member<T, std::void_t<decltype(std::declval<T>().form)>> : std::true_type {};
  }
  template<typename Req>
  bool settings_req_has_file(const Req& req, const std::string& name) {
      if constexpr (yuzu::settings_detail::has_form_member<Req>::value)
          return req.form.has_file(name);
      else
          return req.has_file(name);
  }
  template<typename Req>
  auto settings_req_get_file(const Req& req, const std::string& name) {
      if constexpr (yuzu::settings_detail::has_form_member<Req>::value)
          return req.form.get_file(name);
      else
          return req.get_file_value(name);
  }
  #define SETTINGS_REQ_HAS_FILE(req, name)  settings_req_has_file(req, name)
  #define SETTINGS_REQ_GET_FILE(req, name)  settings_req_get_file(req, name)
#endif

// Settings page HTML template (defined in settings_ui.cpp).
extern const char* const kSettingsHtml;

// GatewayUpstreamServiceImpl and AgentRegistry are inner classes of server.cpp.
// We use callbacks (AgentsJsonFn, GatewaySessionCountFn) to avoid depending on
// their incomplete types.

namespace yuzu::server {

// ── Anonymous namespace: YAML helpers and JSON extraction ────────────────────

namespace {

std::string highlight_yaml_value(const std::string& val) {
    if (val.empty())
        return {};
    auto trimmed = val;
    auto sp = trimmed.find_first_not_of(' ');
    if (sp == std::string::npos)
        return html_escape(val);
    trimmed = trimmed.substr(sp);

    // Booleans
    if (trimmed == "true" || trimmed == "false" || trimmed == "True" || trimmed == "False")
        return "<span class=\"yb\">" + html_escape(val) + "</span>";
    // Numbers
    bool is_number = !trimmed.empty();
    for (char c : trimmed) {
        if (c != '-' && c != '.' && (c < '0' || c > '9')) {
            is_number = false;
            break;
        }
    }
    if (is_number && !trimmed.empty())
        return "<span class=\"yn\">" + html_escape(val) + "</span>";
    // String value (quoted or bare)
    return "<span class=\"yv\">" + html_escape(val) + "</span>";
}

std::string highlight_yaml_kv(const std::string& line) {
    std::size_t i = 0;
    while (i < line.size() && line[i] == ' ')
        ++i;
    auto key_start = i;
    while (i < line.size() && (std::isalnum(static_cast<unsigned char>(line[i])) ||
                               line[i] == '_' || line[i] == '-' || line[i] == '.'))
        ++i;
    if (i >= line.size() || line[i] != ':' || i == key_start)
        return html_escape(line);

    auto indent = line.substr(0, key_start);
    auto key = line.substr(key_start, i - key_start);
    auto rest = line.substr(i + 1);

    bool is_schema = (key == "apiVersion" || key == "kind");
    std::string key_cls = is_schema ? "ya" : "yk";

    return html_escape(indent) + "<span class=\"" + key_cls + "\">" +
           html_escape(key) + "</span>:" + highlight_yaml_value(rest);
}

[[maybe_unused]]
std::string highlight_yaml(std::string_view source) {
    std::string result;
    result.reserve(source.size() * 2);
    int line_num = 1;

    std::size_t pos = 0;
    while (pos <= source.size()) {
        auto nl = source.find('\n', pos);
        std::string line;
        if (nl == std::string_view::npos) {
            line = std::string(source.substr(pos));
            pos = source.size() + 1;
        } else {
            line = std::string(source.substr(pos, nl - pos));
            pos = nl + 1;
        }

        result += "<div class=\"yl\"><span class=\"ln\">" +
                  std::to_string(line_num++) + "</span>";

        auto trimmed_start = line.find_first_not_of(' ');
        if (trimmed_start == std::string::npos) {
            result += "&nbsp;";
        } else if (line[trimmed_start] == '#') {
            result += "<span class=\"yc\">" + html_escape(line) + "</span>";
        } else if (line == "---" || line == "...") {
            result += "<span class=\"yd\">" + html_escape(line) + "</span>";
        } else if (line[trimmed_start] == '-' && trimmed_start + 1 < line.size() &&
                   line[trimmed_start + 1] == ' ') {
            auto indent = line.substr(0, trimmed_start);
            auto after_dash = line.substr(trimmed_start + 2);
            result += html_escape(indent) + "<span class=\"yd\">-</span> ";
            if (after_dash.find(':') != std::string::npos)
                result += highlight_yaml_kv(after_dash);
            else
                result += highlight_yaml_value(after_dash);
        } else if (line.find(':') != std::string::npos) {
            result += highlight_yaml_kv(line);
        } else {
            result += html_escape(line);
        }

        result += "</div>";
    }
    return result;
}

[[maybe_unused]]
std::vector<std::string> validate_yaml_source(const std::string& yaml_source) {
    std::vector<std::string> errors;
    if (yaml_source.empty())
        errors.push_back("YAML source is empty");
    if (yaml_source.find("apiVersion:") == std::string::npos)
        errors.push_back("Missing apiVersion field");
    if (yaml_source.find("kind:") == std::string::npos)
        errors.push_back("Missing kind field");
    if (yaml_source.find("plugin:") == std::string::npos)
        errors.push_back("Missing spec.plugin field");
    if (yaml_source.find("action:") == std::string::npos)
        errors.push_back("Missing spec.action field");
    return errors;
}

std::string extract_json_string(const std::string& body, const std::string& key) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains(key) && j[key].is_string()) {
            return j[key].get<std::string>();
        }
    } catch (...) {}
    return {};
}

} // anonymous namespace

// ── Fragment renderers ──────────────────────────────────────────────────────

std::string SettingsRoutes::render_server_config_fragment() {
    std::string html;

    html += "<table class=\"user-table\" style=\"font-size:0.8rem\">"
            "<thead><tr><th>Setting</th><th>Value</th></tr></thead>"
            "<tbody>";

    html += "<tr><td>Agent gRPC Address</td><td><code>" +
            html_escape(cfg_->listen_address) + "</code></td></tr>";
    html += "<tr><td>Management gRPC Address</td><td><code>" +
            html_escape(cfg_->management_address) + "</code></td></tr>";
    html += "<tr><td>Web UI Address</td><td><code>" +
            html_escape(cfg_->web_address) + "</code></td></tr>";
    html += "<tr><td>Web UI Port</td><td><code>" +
            std::to_string(cfg_->web_port) + "</code></td></tr>";

    html += "<tr><td>Session Timeout</td><td><code>" +
            std::to_string(cfg_->session_timeout.count()) + "s</code></td></tr>";
    html += "<tr><td>Max Agents</td><td><code>" +
            std::to_string(cfg_->max_agents) + "</code></td></tr>";

    std::string auth_path_str = cfg_->auth_config_path.empty()
        ? std::string("(default)")
        : html_escape(cfg_->auth_config_path.string());
    html += "<tr><td>Auth Config Path</td><td><span class=\"file-name\">" +
            auth_path_str + "</span></td></tr>";

    html += "<tr><td>API Rate Limit</td><td><code>" +
            std::to_string(cfg_->rate_limit) + "</code> req/s per IP</td></tr>";
    html += "<tr><td>Login Rate Limit</td><td><code>" +
            std::to_string(cfg_->login_rate_limit) + "</code> req/s per IP</td></tr>";

    html += "</tbody></table>";
    return html;
}

std::string SettingsRoutes::render_tls_fragment() {
    std::string checked = cfg_->tls_enabled ? " checked" : "";
    std::string status_color = cfg_->tls_enabled ? "#3fb950" : "#f85149";
    std::string status_text = cfg_->tls_enabled ? "Enabled" : "Disabled";
    std::string fields_opacity = cfg_->tls_enabled ? "1" : "0.4";

    std::string cert_name =
        cfg_->tls_server_cert.empty() ? "No file" : html_escape(cfg_->tls_server_cert.string());
    std::string key_name =
        cfg_->tls_server_key.empty() ? "No file" : html_escape(cfg_->tls_server_key.string());
    std::string ca_name =
        cfg_->tls_ca_cert.empty() ? "No file" : html_escape(cfg_->tls_ca_cert.string());

    std::string html = "<form id=\"tls-form\">"
           "<div class=\"form-row\">"
           "  <label>gRPC mTLS</label>"
           "  <label class=\"toggle\">"
           "    <input type=\"checkbox\" name=\"tls_enabled\" value=\"true\"" +
           checked +
           "           hx-post=\"/api/settings/tls\" hx-target=\"#tls-feedback\""
           "           hx-swap=\"innerHTML\">"
           "    <span class=\"slider\"></span>"
           "  </label>"
           "  <span style=\"font-size:0.75rem;color:" +
           status_color + ";margin-left:0.5rem\">" + status_text +
           "</span>"
           "</div>"
           "<div style=\"margin-top:1rem;opacity:" +
           fields_opacity +
           "\">"
           "  <div class=\"form-row\">"
           "    <label>Server Certificate</label>"
           "    <div class=\"file-upload\">"
           "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
           "hx-swap=\"innerHTML\""
           "            hx-encoding=\"multipart/form-data\" "
           "style=\"display:flex;align-items:center;gap:0.75rem\">"
           "        <input type=\"hidden\" name=\"type\" value=\"cert\">"
           "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
           "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
           "id=\"cert-file\">"
           "        <button type=\"button\" class=\"btn btn-secondary\""
           "                onclick=\"document.getElementById('cert-file').click()\">Upload "
           "PEM</button>"
           "        <span class=\"file-name\">" +
           cert_name +
           "</span>"
           "      </form>"
           "      <details style=\"margin-top:0.5rem\">"
           "        <summary class=\"btn btn-secondary\" "
           "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
           "        <form hx-post=\"/api/settings/cert-paste\" "
           "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
           "              style=\"margin-top:0.5rem\">"
           "          <input type=\"hidden\" name=\"type\" value=\"cert\">"
           "          <textarea name=\"content\" "
           "            style=\"width:100%;min-height:150px;font-family:monospace;"
           "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
           "                   border:1px solid var(--border);border-radius:4px;"
           "                   padding:0.5rem;resize:vertical\" "
           "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
           "-----END CERTIFICATE-----\"></textarea>"
           "          <button type=\"submit\" class=\"btn btn-primary\" "
           "            style=\"margin-top:0.5rem\">Save</button>"
           "        </form>"
           "      </details>"
           "    </div>"
           "  </div>"
           "  <div class=\"form-row\">"
           "    <label>Server Private Key</label>"
           "    <div class=\"file-upload\">"
           "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
           "hx-swap=\"innerHTML\""
           "            hx-encoding=\"multipart/form-data\" "
           "style=\"display:flex;align-items:center;gap:0.75rem\">"
           "        <input type=\"hidden\" name=\"type\" value=\"key\">"
           "        <input type=\"file\" name=\"file\" accept=\".pem,.key\""
           "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
           "id=\"key-file\">"
           "        <button type=\"button\" class=\"btn btn-secondary\""
           "                onclick=\"document.getElementById('key-file').click()\">Upload "
           "PEM</button>"
           "        <span class=\"file-name\">" +
           key_name +
           "</span>"
           "      </form>"
           "      <details style=\"margin-top:0.5rem\">"
           "        <summary class=\"btn btn-secondary\" "
           "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
           "        <form hx-post=\"/api/settings/cert-paste\" "
           "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
           "              style=\"margin-top:0.5rem\">"
           "          <input type=\"hidden\" name=\"type\" value=\"key\">"
           "          <textarea name=\"content\" "
           "            style=\"width:100%;min-height:150px;font-family:monospace;"
           "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
           "                   border:1px solid var(--border);border-radius:4px;"
           "                   padding:0.5rem;resize:vertical\" "
           "            placeholder=\"-----BEGIN PRIVATE KEY-----&#10;...paste PEM content...&#10;"
           "-----END PRIVATE KEY-----\"></textarea>"
           "          <button type=\"submit\" class=\"btn btn-primary\" "
           "            style=\"margin-top:0.5rem\">Save</button>"
           "        </form>"
           "      </details>"
           "    </div>"
           "  </div>"
           "  <div class=\"form-row\">"
           "    <label>CA Certificate</label>"
           "    <div class=\"file-upload\">"
           "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
           "hx-swap=\"innerHTML\""
           "            hx-encoding=\"multipart/form-data\" "
           "style=\"display:flex;align-items:center;gap:0.75rem\">"
           "        <input type=\"hidden\" name=\"type\" value=\"ca\">"
           "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
           "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
           "id=\"ca-file\">"
           "        <button type=\"button\" class=\"btn btn-secondary\""
           "                onclick=\"document.getElementById('ca-file').click()\">Upload "
           "PEM</button>"
           "        <span class=\"file-name\">" +
           ca_name +
           "</span>"
           "      </form>"
           "      <details style=\"margin-top:0.5rem\">"
           "        <summary class=\"btn btn-secondary\" "
           "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
           "        <form hx-post=\"/api/settings/cert-paste\" "
           "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
           "              style=\"margin-top:0.5rem\">"
           "          <input type=\"hidden\" name=\"type\" value=\"ca\">"
           "          <textarea name=\"content\" "
           "            style=\"width:100%;min-height:150px;font-family:monospace;"
           "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
           "                   border:1px solid var(--border);border-radius:4px;"
           "                   padding:0.5rem;resize:vertical\" "
           "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
           "-----END CERTIFICATE-----\"></textarea>"
           "          <button type=\"submit\" class=\"btn btn-primary\" "
           "            style=\"margin-top:0.5rem\">Save</button>"
           "        </form>"
           "      </details>"
           "    </div>"
           "  </div>"
           "</div>"
           "</form>";

    // Insecure-skip-client-verify (one-way TLS) — color red when enabled to flag the
    // weakened posture in the operator dashboard, not just the warm-orange "warning" hue.
    std::string owt_color = cfg_->allow_one_way_tls ? "#f85149" : "#8b949e";
    std::string owt_text = cfg_->allow_one_way_tls
        ? "Client cert verification DISABLED (--insecure-skip-client-verify)"
        : "Disabled (mTLS enforced)";
    html += "<div class=\"form-row\" style=\"margin-top:0.75rem\">"
            "  <label>Insecure Skip Client Verify</label>"
            "  <span style=\"font-size:0.8rem;color:" + owt_color + "\">" + owt_text + "</span>"
            "</div>";

    // Management TLS overrides
    std::string mgmt_cert = cfg_->mgmt_tls_server_cert.empty() ? "Using agent TLS" : html_escape(cfg_->mgmt_tls_server_cert.string());
    std::string mgmt_key = cfg_->mgmt_tls_server_key.empty() ? "Using agent TLS" : html_escape(cfg_->mgmt_tls_server_key.string());
    std::string mgmt_ca = cfg_->mgmt_tls_ca_cert.empty() ? "Using agent TLS" : html_escape(cfg_->mgmt_tls_ca_cert.string());

    html += "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
            "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
            "Management Listener TLS Override</div>"
            "<div class=\"form-row\">"
            "  <label>Mgmt Certificate</label>"
            "  <span class=\"file-name\">" + mgmt_cert + "</span>"
            "</div>"
            "<div class=\"form-row\">"
            "  <label>Mgmt Private Key</label>"
            "  <span class=\"file-name\">" + mgmt_key + "</span>"
            "</div>"
            "<div class=\"form-row\">"
            "  <label>Mgmt CA Cert</label>"
            "  <span class=\"file-name\">" + mgmt_ca + "</span>"
            "</div>"
            "</div>";

    html += "<div class=\"feedback\" id=\"tls-feedback\"></div>";
    return html;
}

std::string SettingsRoutes::render_users_fragment(const std::string& current_username) {
    auto users = auth_mgr_->list_users();
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>"
                       "  <tbody>";

    if (users.empty()) {
        html += "<tr><td colspan=\"3\" style=\"color:#484f58\">No users</td></tr>";
    } else {
        for (const auto& u : users) {
            auto role_str = auth::role_to_string(u.role);
            auto cls = (u.role == auth::Role::admin) ? "role-admin" : "role-user";
            const bool is_self =
                !current_username.empty() && u.username == current_username;
            html += "<tr><td>" + html_escape(u.username) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    std::string(cls) + "\">" + html_escape(role_str) +
                    "</span></td>"
                    "<td>";
            if (is_self) {
                // Self-deletion lockout guard (#397/#403): the Remove button
                // is suppressed for the currently authenticated operator's
                // own row so that deleting the sole admin — and thereby
                // locking every user out of the running server — is not a
                // two-click operation in the dashboard. The DELETE handler
                // also rejects self-targeted requests; both halves are load-
                // bearing because the UI guard alone does not stop a hand-
                // crafted HTTP DELETE.
                html += "<span class=\"current-user-badge\" "
                        "style=\"color:#484f58;font-size:0.7rem;"
                        "font-style:italic\" "
                        "title=\"You cannot remove your own account\">"
                        "Current user</span>";
            } else {
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/users/" +
                        html_escape(u.username) +
                        "\" "
                        "hx-target=\"#user-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Remove user &quot;" +
                        html_escape(u.username) +
                        "&quot;?\""
                        ">Remove</button>";
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/users\" "
            "      hx-target=\"#user-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Username</label>"
            "    <input type=\"text\" name=\"username\" placeholder=\"username\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Password <span style=\"color:#8b949e;font-weight:normal;"
            "font-size:0.7rem\">(min 12 chars)</span></label>"
            "    <input type=\"password\" name=\"password\" placeholder=\"password\" "
            "           minlength=\"12\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Role</label>"
            "    <select name=\"role\">"
            "      <option value=\"user\">User</option>"
            "      <option value=\"admin\">Admin</option>"
            "    </select>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Add User</button>"
            "</form>"
            "<div class=\"feedback\" id=\"user-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_tokens_fragment(const std::string& new_raw_token) {
    auto tokens = auth_mgr_->list_enrollment_tokens();
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
                       "  <th>Expires</th><th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (tokens.empty()) {
        html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No tokens created</td></tr>";
    } else {
        for (const auto& t : tokens) {
            auto uses = t.max_uses == 0
                            ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                            : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);

            std::string exp;
            if (t.expires_at == (std::chrono::system_clock::time_point::max)()) {
                exp = "Never";
            } else {
                auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                 t.expires_at.time_since_epoch())
                                 .count();
                exp = std::to_string(epoch);
            }

            std::string status_cls, status_txt;
            if (t.revoked) {
                status_cls = "role-user";
                status_txt = "Revoked";
            } else if (t.max_uses > 0 && t.use_count >= t.max_uses) {
                status_cls = "role-user";
                status_txt = "Exhausted";
            } else {
                status_cls = "role-admin";
                status_txt = "Active";
            }

            html += "<tr><td><code>" + html_escape(t.token_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(t.label) +
                    "</td>"
                    "<td>" +
                    uses +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    exp +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\">" + status_txt +
                    "</span></td>"
                    "<td>";
            if (!t.revoked) {
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/enrollment-tokens/" +
                        html_escape(t.token_id) +
                        "\" "
                        "hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke token &quot;" +
                        html_escape(t.token_id) +
                        "&quot;? Agents using this token will no longer be able to enroll.\""
                        ">Revoke</button>";
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/enrollment-tokens\" "
            "      hx-target=\"#token-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Label</label>"
            "    <input type=\"text\" name=\"label\" placeholder=\"e.g. NYC rollout\" "
            "style=\"width:160px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Max Uses</label>"
            "    <input type=\"text\" name=\"max_uses\" placeholder=\"0 = unlimited\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>TTL (hours)</label>"
            "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Generate Token</button>"
            "</form>"
            "<div class=\"feedback\" id=\"token-feedback\"></div>";

    if (!new_raw_token.empty()) {
        html += "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    COPY THIS TOKEN NOW — it will not be shown again"
                "  </div>"
                "  <code>" +
                html_escape(new_raw_token) +
                "</code><br>"
                "  <button class=\"btn btn-secondary\" "
                "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                "          data-copy-token>Copy to Clipboard</button>"
                "</div>";
    }

    return html;
}

std::string SettingsRoutes::render_api_tokens_fragment(const std::string& new_raw_token,
                                                        const std::string& filter_principal) {
    if (!api_token_store_ || !api_token_store_->is_open()) {
        return "<span style=\"color:#484f58\">API token store unavailable.</span>";
    }

    auto fmt_epoch = [](int64_t epoch) -> std::string {
        if (epoch == 0)
            return "Never";
        auto tt = static_cast<std::time_t>(epoch);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &tt);
#else
        gmtime_r(&tt, &tm_buf);
#endif
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
        return std::string(buf) + " UTC";
    };

    // Scope by caller principal for non-admin sessions. list_tokens already
    // supports a principal_id filter — the same one used by
    // `GET /api/v1/tokens` at rest_api_v1.cpp:826 — so admins get the full
    // fleet view while regular users see only their own tokens. Closes the
    // cross-user token enumeration path that governance Gate 4 consistency
    // auditor flagged as BLOCKING (finding C1).
    auto tokens = api_token_store_->list_tokens(filter_principal);
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Owner</th>"
                       "  <th>Created</th><th>Expires</th><th>Last Used</th>"
                       "  <th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (tokens.empty()) {
        html += "<tr><td colspan=\"9\" style=\"color:#484f58\">No API tokens created</td></tr>";
    } else {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        for (const auto& t : tokens) {
            std::string exp =
                t.expires_at == 0 ? "Never" : fmt_epoch(t.expires_at);

            bool expired = t.expires_at > 0 && t.expires_at < now;

            std::string status_cls, status_txt;
            if (t.revoked) {
                status_cls = "role-user";
                status_txt = "Revoked";
            } else if (expired) {
                status_cls = "role-user";
                status_txt = "Expired";
            } else {
                status_cls = "role-admin";
                status_txt = "Active";
            }

            std::string type_text = t.mcp_tier.empty() ? "API" : "MCP";
            std::string type_detail = t.mcp_tier.empty() ? "" : " (" + html_escape(t.mcp_tier) + ")";
            std::string type_color = t.mcp_tier.empty() ? "#484f58" : "#8957e5";

            html += "<tr><td><code>" + html_escape(t.token_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(t.name) +
                    "</td>"
                    "<td><span class=\"role-badge\" style=\"background:" + type_color + ";color:#fff\">" +
                    type_text + "</span>" + type_detail +
                    "</td>"
                    "<td>" +
                    html_escape(t.principal_id) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    fmt_epoch(t.created_at) +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    exp +
                    "</td>"
                    "<td style=\"font-size:0.75rem\">" +
                    fmt_epoch(t.last_used_at) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\">" + status_txt +
                    "</span></td>"
                    "<td>";
            if (!t.revoked) {
                html += "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/api-tokens/" +
                        html_escape(t.token_id) +
                        "\" "
                        "hx-target=\"#api-token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke API token &quot;" +
                        html_escape(t.token_id) +
                        "&quot;? Applications using this token will lose access.\""
                        ">Revoke</button>";
            }
            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/api-tokens\" "
            "      hx-target=\"#api-token-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Name</label>"
            "    <input type=\"text\" name=\"name\" placeholder=\"e.g. CI/CD pipeline\" "
            "style=\"width:160px\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>TTL (hours)</label>"
            "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
            "style=\"width:80px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>MCP Tier</label>"
            "    <select name=\"mcp_tier\" style=\"width:120px\">"
            "      <option value=\"\">(none — API)</option>"
            "      <option value=\"readonly\">readonly</option>"
            "      <option value=\"operator\">operator</option>"
            "      <option value=\"supervised\">supervised</option>"
            "    </select>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Create Token</button>"
            "</form>"
            "<div class=\"feedback\" id=\"api-token-feedback\"></div>";

    if (!new_raw_token.empty()) {
        html += "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    COPY THIS API TOKEN NOW — it will not be shown again"
                "  </div>"
                "  <code>" +
                html_escape(new_raw_token) +
                "</code><br>"
                "  <button class=\"btn btn-secondary\" "
                "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                "          data-copy-token>Copy to Clipboard</button>"
                "</div>";
    }

    return html;
}

std::string SettingsRoutes::render_pending_fragment() {
    auto all_agents = auth_mgr_->list_pending_agents();
    // Filter out enrolled (approved) agents — they don't need admin attention.
    // Only show pending and denied entries in the approval queue.
    std::vector<auth::PendingAgent> agents;
    for (auto& a : all_agents) {
        if (a.status != auth::PendingStatus::approved) {
            agents.push_back(std::move(a));
        }
    }
    std::string html = "<table class=\"user-table\">"
                       "  <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th>"
                       "  <th>Version</th><th>Status</th><th></th></tr></thead>"
                       "  <tbody>";

    if (agents.empty()) {
        html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No pending agents</td></tr>";
    } else {
        for (const auto& a : agents) {
            auto status_str = auth::pending_status_to_string(a.status);
            std::string status_cls, status_style;
            if (a.status == auth::PendingStatus::approved) {
                status_cls = "role-admin";
            } else if (a.status == auth::PendingStatus::denied) {
                status_cls = "role-user";
            } else {
                status_style = "background:var(--yellow);color:#000";
            }

            auto short_id =
                a.agent_id.size() > 12 ? a.agent_id.substr(0, 12) + "..." : a.agent_id;

            html += "<tr>"
                    "<td><code style=\"font-size:0.7rem\">" +
                    html_escape(short_id) +
                    "</code></td>"
                    "<td>" +
                    html_escape(a.hostname) +
                    "</td>"
                    "<td>" +
                    html_escape(a.os) + " " + html_escape(a.arch) +
                    "</td>"
                    "<td>" +
                    html_escape(a.agent_version) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    status_cls + "\" style=\"" + status_style + "\">" +
                    html_escape(status_str) +
                    "</span></td>"
                    "<td>";

            if (a.status == auth::PendingStatus::pending) {
                html += "<button class=\"btn btn-primary\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem;margin-right:0.3rem\" "
                        "hx-post=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "/approve\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                        ">Approve</button>"
                        "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-post=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "/deny\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Deny agent enrollment?\""
                        ">Deny</button>";
            } else {
                html += "<button class=\"btn btn-secondary\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/pending-agents/" +
                        html_escape(a.agent_id) +
                        "\" "
                        "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                        ">Remove</button>";
            }

            html += "</td></tr>";
        }
    }

    html += "  </tbody>"
            "</table>";

    auto pending_count = std::count_if(agents.begin(), agents.end(), [](const auto& a) {
        return a.status == auth::PendingStatus::pending;
    });
    if (pending_count > 1) {
        html += "<div style=\"margin-top:0.75rem;display:flex;gap:0.5rem\">"
                "<button class=\"btn btn-primary\" "
                "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                "onclick=\"twoClickConfirm(this, function() { "
                "htmx.ajax('POST','/api/settings/pending-agents/bulk-approve',"
                "{target:'#pending-section',swap:'innerHTML'}); })\">"
                "Approve All (" + std::to_string(pending_count) + ")</button>"
                "<button class=\"btn btn-danger\" "
                "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                "onclick=\"twoClickConfirm(this, function() { "
                "htmx.ajax('POST','/api/settings/pending-agents/bulk-deny',"
                "{target:'#pending-section',swap:'innerHTML'}); })\">"
                "Deny All (" + std::to_string(pending_count) + ")</button>"
                "</div>";
    }

    html += "<div class=\"feedback\" id=\"pending-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_auto_approve_fragment() {
    auto rules = auto_approve_->list_rules();
    std::string html;

    html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
            "<label>Match mode</label>"
            "<select name=\"mode\" "
            "hx-post=\"/api/settings/auto-approve/mode\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
            "style=\"flex:0 0 auto;width:180px\">"
            "<option value=\"any\"" +
            std::string(auto_approve_->require_all() ? "" : " selected") +
            ">Any rule (first match)</option>"
            "<option value=\"all\"" +
            std::string(auto_approve_->require_all() ? " selected" : "") +
            ">All rules must match</option>"
            "</select>"
            "</div>";

    html += "<table class=\"user-table\">"
            "<thead><tr><th>Type</th><th>Value</th><th>Label</th>"
            "<th>Enabled</th><th></th></tr></thead><tbody>";

    if (rules.empty()) {
        html += "<tr><td colspan=\"5\" style=\"color:#484f58\">No auto-approve rules "
                "configured</td></tr>";
    } else {
        auto type_str = [](auth::AutoApproveRuleType t) -> std::string {
            switch (t) {
            case auth::AutoApproveRuleType::trusted_ca:
                return "Trusted CA";
            case auth::AutoApproveRuleType::hostname_glob:
                return "Hostname Glob";
            case auth::AutoApproveRuleType::ip_subnet:
                return "IP Subnet";
            case auth::AutoApproveRuleType::cloud_provider:
                return "Cloud Provider";
            }
            return "Unknown";
        };

        for (size_t i = 0; i < rules.size(); ++i) {
            const auto& r = rules[i];
            auto idx = std::to_string(i);
            html += "<tr>"
                    "<td>" +
                    html_escape(type_str(r.type)) +
                    "</td>"
                    "<td><code style=\"font-size:0.75rem\">" +
                    html_escape(r.value) +
                    "</code></td>"
                    "<td>" +
                    html_escape(r.label) +
                    "</td>"
                    "<td>"
                    "<label class=\"toggle\">"
                    "<input type=\"checkbox\"" +
                    std::string(r.enabled ? " checked" : "") +
                    " hx-post=\"/api/settings/auto-approve/" + idx +
                    "/toggle\" "
                    "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\">"
                    "<span class=\"slider\"></span></label></td>"
                    "<td><button class=\"btn btn-danger\" "
                    "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                    "hx-delete=\"/api/settings/auto-approve/" +
                    idx +
                    "\" "
                    "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Remove this auto-approve rule?\" "
                    ">Remove</button></td></tr>";
        }
    }

    html += "</tbody></table>";

    html += "<div class=\"add-user-form\">"
            "<form hx-post=\"/api/settings/auto-approve\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
            "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
            "<div class=\"mini-field\">"
            "<label>Type</label>"
            "<select name=\"type\" style=\"width:140px\">"
            "<option value=\"hostname_glob\">Hostname Glob</option>"
            "<option value=\"ip_subnet\">IP Subnet</option>"
            "<option value=\"trusted_ca\">Trusted CA</option>"
            "<option value=\"cloud_provider\">Cloud Provider</option>"
            "</select></div>"
            "<div class=\"mini-field\" style=\"flex:1\">"
            "<label>Value</label>"
            "<input type=\"text\" name=\"value\" placeholder=\"*.prod.example.com\" required>"
            "</div>"
            "<div class=\"mini-field\" style=\"flex:1\">"
            "<label>Label</label>"
            "<input type=\"text\" name=\"label\" placeholder=\"Production servers\">"
            "</div>"
            "<button class=\"btn btn-primary\" type=\"submit\">Add Rule</button>"
            "</form></div>"
            "<div class=\"feedback\" id=\"auto-approve-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_tag_compliance_fragment() {
    const auto& categories = get_tag_categories();

    std::string html;
    html += "<table class=\"user-table\">"
            "<thead><tr>"
            "<th>Category</th>"
            "<th>Display Name</th>"
            "<th>Agents Tagged</th>"
            "<th>Agents Missing</th>"
            "<th>Allowed Values</th>"
            "</tr></thead><tbody>";

    auto gaps = tag_store_ ? tag_store_->get_compliance_gaps()
                           : std::vector<std::pair<std::string, std::vector<std::string>>>{};

    std::unordered_map<std::string, int> missing_count;
    for (const auto& [agent_id, missing] : gaps) {
        for (const auto& k : missing)
            missing_count[k]++;
    }

    size_t total_agents = 0;
    if (tag_store_) {
        std::unordered_set<std::string> seen;
        for (const auto& [aid, m] : gaps)
            seen.insert(aid);
        for (auto cat_key : kCategoryKeys) {
            auto agents = tag_store_->agents_with_tag(std::string(cat_key));
            for (const auto& a : agents)
                seen.insert(a);
        }
        total_agents = seen.size();
    }

    for (const auto& cat : categories) {
        std::string key_str(cat.key);
        int tagged = 0;
        if (tag_store_)
            tagged = static_cast<int>(tag_store_->agents_with_tag(key_str).size());
        int missing = missing_count.count(key_str) ? missing_count[key_str] : 0;

        std::string vals_str;
        if (cat.allowed_values.empty()) {
            vals_str = "<span style=\"color:#8b949e\">Free-form</span>";
        } else {
            for (size_t i = 0; i < cat.allowed_values.size(); ++i) {
                if (i > 0)
                    vals_str += ", ";
                vals_str += std::string(cat.allowed_values[i]);
            }
        }

        std::string missing_style =
            missing > 0 ? "color:#f85149;font-weight:600" : "color:#3fb950";
        html += "<tr><td><code>" + key_str + "</code></td>";
        html += "<td>" + std::string(cat.display_name) + "</td>";
        html += "<td>" + std::to_string(tagged) + "</td>";
        html += "<td style=\"" + missing_style + "\">" + std::to_string(missing) + "</td>";
        html += "<td>" + vals_str + "</td></tr>";
    }

    html += "</tbody></table>";

    if (total_agents > 0) {
        size_t compliant = total_agents - gaps.size();
        html += "<div style=\"margin-top:0.75rem;font-size:0.75rem;color:#8b949e\">"
                "Compliance: " +
                std::to_string(compliant) + "/" + std::to_string(total_agents) +
                " agents have all required tags</div>";
    }

    return html;
}

std::string SettingsRoutes::render_management_groups_fragment() {
    if (!mgmt_group_store_ || !mgmt_group_store_->is_open())
        return "<span style=\"color:#484f58\">Management group store not available</span>";

    auto groups = mgmt_group_store_->list_groups();

    std::unordered_map<std::string, std::vector<const ManagementGroup*>> children_map;
    std::vector<const ManagementGroup*> roots;
    for (const auto& g : groups) {
        if (g.parent_id.empty())
            roots.push_back(&g);
        else
            children_map[g.parent_id].push_back(&g);
    }

    std::sort(roots.begin(), roots.end(), [](const ManagementGroup* a, const ManagementGroup* b) {
        if (a->id == ManagementGroupStore::kRootGroupId)
            return true;
        if (b->id == ManagementGroupStore::kRootGroupId)
            return false;
        return a->name < b->name;
    });

    std::string html;

    html += "<div style=\"margin-bottom:0.75rem;font-size:0.75rem;color:#8b949e\">"
            "Total groups: " +
            std::to_string(groups.size()) + " &middot; Total memberships: " +
            std::to_string(mgmt_group_store_->count_all_members()) + "</div>";

    html += "<table class=\"user-table\">"
            "<thead><tr>"
            "<th>Group</th>"
            "<th>Type</th>"
            "<th>Members</th>"
            "<th>Actions</th>"
            "</tr></thead><tbody>";

    std::function<void(const ManagementGroup*, int)> render_node =
        [&](const ManagementGroup* g, int depth) {
            auto member_count = mgmt_group_store_->count_members(g->id);
            bool is_root = (g->id == ManagementGroupStore::kRootGroupId);

            std::string indent;
            for (int i = 0; i < depth; ++i)
                indent += "&nbsp;&nbsp;&nbsp;&nbsp;";
            if (depth > 0)
                indent += "<span style=\"color:#484f58\">&boxur;</span> ";

            std::string name_style = is_root ? "font-weight:600" : "";
            std::string type_badge;
            if (g->membership_type == "dynamic") {
                type_badge = "<span style=\"background:#1f6feb;color:#fff;padding:1px 6px;"
                             "border-radius:3px;font-size:0.7rem\">dynamic</span>";
            } else {
                type_badge = "<span style=\"background:#484f58;color:#c9d1d9;padding:1px 6px;"
                             "border-radius:3px;font-size:0.7rem\">static</span>";
            }

            html += "<tr>";
            html += "<td>" + indent + "<span style=\"" + name_style + "\">" + g->name +
                     "</span></td>";
            html += "<td>" + type_badge + "</td>";
            html += "<td>" + std::to_string(member_count) + "</td>";
            html += "<td>";
            if (!is_root) {
                html +=
                    "<button class=\"btn btn-sm\" "
                    "hx-delete=\"/api/settings/management-groups/" +
                    g->id +
                    "\" "
                    "hx-target=\"#mgmt-groups-section\" "
                    "hx-confirm=\"Delete group '" +
                    g->name +
                    "' and all children?\" "
                    "style=\"font-size:0.7rem;padding:1px 6px;color:#f85149;border-color:#f85149"
                    "\">Delete</button>";
            }
            html += "</td></tr>";

            auto it = children_map.find(g->id);
            if (it != children_map.end()) {
                auto sorted_children = it->second;
                std::sort(sorted_children.begin(), sorted_children.end(),
                          [](const ManagementGroup* a, const ManagementGroup* b) {
                              return a->name < b->name;
                          });
                for (const auto* child : sorted_children)
                    render_node(child, depth + 1);
            }
        };

    for (const auto* root : roots)
        render_node(root, 0);

    html += "</tbody></table>";

    html +=
        "<div style=\"margin-top:0.75rem\">"
        "<details><summary style=\"cursor:pointer;color:#58a6ff;font-size:0.8rem\">"
        "Create group</summary>"
        "<form hx-post=\"/api/settings/management-groups\" "
        "hx-target=\"#mgmt-groups-section\" "
        "hx-swap=\"innerHTML\" "
        "style=\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem;align-items:end\">"
        "<div><label style=\"font-size:0.7rem;color:#8b949e\">Name</label>"
        "<input type=\"text\" name=\"name\" required "
        "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
        "padding:4px 8px;border-radius:4px;font-size:0.8rem\"></div>"
        "<div><label style=\"font-size:0.7rem;color:#8b949e\">Parent</label>"
        "<select name=\"parent_id\" "
        "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
        "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
        "<option value=\"\">— root —</option>";
    for (const auto& g : groups) {
        html += "<option value=\"" + g.id + "\">" + g.name + "</option>";
    }
    html +=
        "</select></div>"
        "<div><label style=\"font-size:0.7rem;color:#8b949e\">Type</label>"
        "<select name=\"membership_type\" "
        "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
        "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
        "<option value=\"static\">static</option>"
        "<option value=\"dynamic\">dynamic</option>"
        "</select></div>"
        "<button type=\"submit\" class=\"btn\" "
        "style=\"font-size:0.8rem;padding:4px 12px\">Create</button>"
        "</form></details></div>";

    return html;
}

std::string SettingsRoutes::render_updates_fragment() {
    std::string html;

    std::string ota_color = cfg_->ota_enabled ? "#3fb950" : "#484f58";
    std::string ota_text = cfg_->ota_enabled ? "Enabled" : "Disabled";
    html += "<div class=\"form-row\">"
            "  <label>OTA Updates</label>"
            "  <span style=\"font-size:0.8rem;color:" + ota_color + ";font-weight:600\">" +
            ota_text + "</span>"
            "</div>";

    std::string update_dir_str = cfg_->update_dir.empty()
        ? std::string("(default)")
        : html_escape(cfg_->update_dir.string());
    html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
            "  <label>Update Directory</label>"
            "  <span class=\"file-name\">" + update_dir_str + "</span>"
            "</div>";

    if (!update_registry_) {
        html += "<span style=\"color:#484f58\">OTA updates are disabled "
                "(start server with <code>--ota-enabled</code>).</span>";
        return html;
    }

    auto packages = update_registry_->list_packages();

    // Fleet version summary — use the callback to avoid incomplete-type dep
    if (agents_json_fn_) {
        auto agents_json_str = agents_json_fn_();
        std::unordered_map<std::string, int> version_counts;
        try {
            auto arr = nlohmann::json::parse(agents_json_str);
            for (const auto& a : arr) {
                auto v = a.value("agent_version", std::string("unknown"));
                version_counts[v]++;
            }
        } catch (...) {}

        if (!version_counts.empty()) {
            html += "<div style=\"margin-bottom:1rem;padding:0.5rem 0.75rem;"
                    "background:#0d1117;border:1px solid #30363d;border-radius:0.3rem\">"
                    "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                    "margin-bottom:0.3rem;text-transform:uppercase;letter-spacing:0.05em\">"
                    "Fleet Versions</div>";
            for (const auto& [ver, cnt] : version_counts) {
                html += "<span style=\"display:inline-block;margin-right:1rem;"
                        "font-size:0.75rem\"><code>" +
                        html_escape(ver) + "</code> &times; " + std::to_string(cnt) + "</span>";
            }
            html += "</div>";
        }
    }

    html += "<table class=\"user-table\">"
            "<thead><tr><th>Platform</th><th>Arch</th><th>Version</th>"
            "<th>Size</th><th>Rollout</th><th>Mandatory</th><th></th></tr></thead>"
            "<tbody>";

    if (packages.empty()) {
        html += "<tr><td colspan=\"7\" style=\"color:#484f58\">"
                "No update packages uploaded</td></tr>";
    } else {
        for (const auto& pkg : packages) {
            auto size_str = pkg.file_size < 1024 * 1024
                                ? std::to_string(pkg.file_size / 1024) + " KB"
                                : std::to_string(pkg.file_size / (1024 * 1024)) + " MB";

            html += "<tr>"
                    "<td>" +
                    html_escape(pkg.platform) +
                    "</td>"
                    "<td>" +
                    html_escape(pkg.arch) +
                    "</td>"
                    "<td><code style=\"font-size:0.75rem\">" +
                    html_escape(pkg.version) +
                    "</code></td>"
                    "<td style=\"font-size:0.75rem\">" +
                    size_str +
                    "</td>"
                    "<td>"
                    "<form style=\"display:flex;align-items:center;gap:0.4rem\" "
                    "hx-post=\"/api/settings/updates/" +
                    html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                    html_escape(pkg.version) +
                    "/rollout\" "
                    "hx-target=\"#updates-section\" hx-swap=\"innerHTML\">"
                    "<input type=\"range\" name=\"rollout_pct\" min=\"0\" max=\"100\" "
                    "value=\"" +
                    std::to_string(pkg.rollout_pct) +
                    "\" "
                    "style=\"width:60px\" "
                    "onchange=\"this.nextElementSibling.textContent=this.value+'%'\">"
                    "<span style=\"font-size:0.7rem;width:2.5em\">" +
                    std::to_string(pkg.rollout_pct) +
                    "%</span>"
                    "<button class=\"btn btn-secondary\" type=\"submit\" "
                    "style=\"padding:0.15rem 0.5rem;font-size:0.65rem\">Set</button>"
                    "</form></td>"
                    "<td style=\"font-size:0.75rem\">" +
                    std::string(pkg.mandatory ? "Yes" : "No") +
                    "</td>"
                    "<td><button class=\"btn btn-danger\" "
                    "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                    "hx-delete=\"/api/settings/updates/" +
                    html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                    html_escape(pkg.version) +
                    "\" "
                    "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Delete update package " +
                    html_escape(pkg.version) + " for " + html_escape(pkg.platform) + "/" +
                    html_escape(pkg.arch) +
                    "?\""
                    ">Delete</button></td></tr>";
        }
    }

    html += "</tbody></table>";

    html +=
        "<div class=\"add-user-form\">"
        "<form hx-post=\"/api/settings/updates/upload\" "
        "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
        "hx-encoding=\"multipart/form-data\" "
        "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
        "<div class=\"mini-field\">"
        "<label>Platform</label>"
        "<select name=\"platform\" style=\"width:100px\">"
        "<option value=\"windows\">Windows</option>"
        "<option value=\"linux\">Linux</option>"
        "<option value=\"darwin\">macOS</option>"
        "</select></div>"
        "<div class=\"mini-field\">"
        "<label>Arch</label>"
        "<select name=\"arch\" style=\"width:100px\">"
        "<option value=\"x86_64\">x86_64</option>"
        "<option value=\"aarch64\">aarch64</option>"
        "</select></div>"
        "<div class=\"mini-field\">"
        "<label>Binary</label>"
        "<input type=\"file\" name=\"file\" required></div>"
        "<div class=\"mini-field\">"
        "<label>Rollout %</label>"
        "<input type=\"text\" name=\"rollout_pct\" value=\"100\" style=\"width:50px\"></div>"
        "<div class=\"mini-field\" style=\"display:flex;align-items:center;gap:0.3rem\">"
        "<label>Mandatory</label>"
        "<input type=\"checkbox\" name=\"mandatory\" value=\"true\"></div>"
        "<button class=\"btn btn-primary\" type=\"submit\">Upload</button>"
        "</form></div>"
        "<div class=\"feedback\" id=\"updates-feedback\"></div>";

    return html;
}

std::string SettingsRoutes::render_gateway_fragment() {
    bool enabled = gateway_enabled_;
    std::string status_color = enabled ? "#3fb950" : "#484f58";
    std::string status_text = enabled ? "Enabled" : "Disabled";

    std::string html;

    html += "<div class=\"form-row\">"
            "  <label>Upstream Service</label>"
            "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
            status_text + "</span>"
            "</div>";

    if (enabled) {
        html += "<div class=\"form-row\">"
                "  <label>Listen Address</label>"
                "  <code style=\"font-size:0.8rem\">" +
                html_escape(cfg_->gateway_upstream_address) +
                "</code>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Gateway Mode</label>"
                "  <span style=\"font-size:0.8rem;color:" +
                std::string(cfg_->gateway_mode ? "#3fb950" : "#8b949e") + "\">" +
                (cfg_->gateway_mode ? "Active" : "Inactive") +
                "</span>"
                "</div>";

        auto count = gateway_session_count_fn_ ? gateway_session_count_fn_() : 0;
        html += "<div class=\"form-row\">"
                "  <label>Active Sessions</label>"
                "  <span style=\"font-size:0.8rem\">" + std::to_string(count) +
                " agent" + (count != 1 ? "s" : "") + " via gateway</span>"
                "</div>";
    } else {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "The gateway upstream service is not running. Start the server with "
                "<code>--gateway-upstream 0.0.0.0:50055</code> to enable it.</p>";
    }

    html += "<div style=\"margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
            "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
            "Erlang Gateway Environment Variables</div>"
            "<table class=\"user-table\" style=\"font-size:0.75rem\">"
            "<thead><tr><th>Variable</th><th>Description</th><th>Default</th></tr></thead>"
            "<tbody>"
            "<tr><td><code>YUZU_GW_UPSTREAM_ADDR</code></td>"
            "    <td>C++ server hostname</td><td><code>127.0.0.1</code></td></tr>"
            "<tr><td><code>YUZU_GW_UPSTREAM_PORT</code></td>"
            "    <td>C++ server port</td><td><code>50055</code></td></tr>"
            "<tr><td><code>YUZU_GW_AGENT_PORT</code></td>"
            "    <td>Agent-facing listener port</td><td><code>50051</code></td></tr>"
            "<tr><td><code>YUZU_GW_MGMT_PORT</code></td>"
            "    <td>Management listener port</td><td><code>50052</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_ENABLED</code></td>"
            "    <td>TLS master switch</td><td><code>auto</code></td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CERTFILE</code></td>"
            "    <td>Gateway certificate path</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_KEYFILE</code></td>"
            "    <td>Gateway private key path</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_TLS_CACERTFILE</code></td>"
            "    <td>CA certificate bundle</td><td>&mdash;</td></tr>"
            "<tr><td><code>YUZU_GW_PROMETHEUS_PORT</code></td>"
            "    <td>Prometheus metrics port</td><td><code>9568</code></td></tr>"
            "<tr><td><code>YUZU_GW_HEALTH_PORT</code></td>"
            "    <td>Health endpoint port</td><td><code>8080</code></td></tr>"
            "</tbody></table>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_https_fragment() {
    std::string html;

    std::string status_color = cfg_->https_enabled ? "#3fb950" : "#484f58";
    std::string status_text = cfg_->https_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>HTTPS</label>"
            "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
            status_text + "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>HTTPS Port</label>"
            "  <code style=\"font-size:0.8rem\">" + std::to_string(cfg_->https_port) + "</code>"
            "</div>";

    std::string https_cert = cfg_->https_cert_path.empty() ? "Not configured" : html_escape(cfg_->https_cert_path.string());
    std::string https_key = cfg_->https_key_path.empty() ? "Not configured" : html_escape(cfg_->https_key_path.string());

    html += "<div class=\"form-row\">"
            "  <label>Certificate</label>"
            "  <span class=\"file-name\">" + https_cert + "</span>"
            "</div>";
    html += "<div class=\"form-row\">"
            "  <label>Private Key</label>"
            "  <span class=\"file-name\">" + https_key + "</span>"
            "</div>";

    std::string redir_color = cfg_->https_redirect ? "#3fb950" : "#8b949e";
    std::string redir_text = cfg_->https_redirect ? "Enabled" : "Disabled";
    html += "<div class=\"form-row\">"
            "  <label>HTTP Redirect</label>"
            "  <span style=\"font-size:0.8rem;color:" + redir_color + "\">" + redir_text + "</span>"
            "</div>";

    if (!cfg_->https_enabled) {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "Start the server with <code>--https --https-cert &lt;path&gt; --https-key &lt;path&gt;</code> to enable.</p>";
    }

    return html;
}

std::string SettingsRoutes::render_analytics_fragment() {
    std::string html;

    std::string status_color = cfg_->analytics_enabled ? "#3fb950" : "#484f58";
    std::string status_text = cfg_->analytics_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>Analytics</label>"
            "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
            status_text + "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Drain Interval</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->analytics_drain_interval_seconds) + "s</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Batch Size</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->analytics_batch_size) + "</code>"
            "</div>";

    bool ch_configured = !cfg_->clickhouse_url.empty();
    std::string ch_color = ch_configured ? "#3fb950" : "#484f58";
    std::string ch_text = ch_configured ? html_escape(cfg_->clickhouse_url) : "Not configured";

    html += "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
            "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
            "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
            "ClickHouse Integration</div>";
    html += "<div class=\"form-row\">"
            "  <label>URL</label>"
            "  <span style=\"font-size:0.8rem;color:" + ch_color + "\">" + ch_text + "</span>"
            "</div>";
    if (ch_configured) {
        html += "<div class=\"form-row\">"
                "  <label>Database</label>"
                "  <code style=\"font-size:0.8rem\">" + html_escape(cfg_->clickhouse_database) + "</code>"
                "</div>";
        html += "<div class=\"form-row\">"
                "  <label>Table</label>"
                "  <code style=\"font-size:0.8rem\">" + html_escape(cfg_->clickhouse_table) + "</code>"
                "</div>";
        html += "<div class=\"form-row\">"
                "  <label>Username</label>"
                "  <code style=\"font-size:0.8rem\">" +
                (cfg_->clickhouse_username.empty() ? std::string("(default)") : html_escape(cfg_->clickhouse_username)) +
                "</code></div>";
        html += "<div class=\"form-row\">"
                "  <label>Password</label>"
                "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
                (cfg_->clickhouse_password.empty() ? std::string("(not set)") : std::string("********")) +
                "</span></div>";
    }
    html += "</div>";

    std::string jsonl_path = cfg_->analytics_jsonl_path.empty() ? "Not configured" : html_escape(cfg_->analytics_jsonl_path.string());
    html += "<div class=\"form-row\" style=\"margin-top:0.5rem\">"
            "  <label>JSONL Export</label>"
            "  <span class=\"file-name\">" + jsonl_path + "</span>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_data_retention_fragment() {
    std::string html;

    html += "<div class=\"form-row\">"
            "  <label>Response Data</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->response_retention_days) + " days</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Audit Logs</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->audit_retention_days) + " days</code>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_mcp_fragment() {
    std::string html;
    bool mcp_enabled = !cfg_->mcp_disable;

    std::string status_color = mcp_enabled ? "#3fb950" : "#484f58";
    std::string status_text = mcp_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>Status</label>"
            "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
            status_text + "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Endpoint</label>"
            "  <code style=\"font-size:0.8rem\">POST /mcp/v1/</code>"
            "</div>";

    std::string enabled_checked = mcp_enabled ? " checked" : "";
    html += "<form hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\" hx-swap=\"innerHTML\">"
            "<div class=\"form-row\">"
            "  <label>MCP Enabled</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"hidden\" name=\"enabled\" value=\"false\">"
            "    <input type=\"checkbox\" name=\"enabled\" value=\"true\"" +
            enabled_checked + " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
            " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "</div>";

    std::string readonly_checked = cfg_->mcp_read_only ? " checked" : "";
    std::string readonly_color = cfg_->mcp_read_only ? "#d29922" : "#484f58";
    std::string readonly_text = cfg_->mcp_read_only ? "Read-Only" : "Full Access";
    html += "<div class=\"form-row\">"
            "  <label>Access Mode</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"hidden\" name=\"read_only\" value=\"false\">"
            "    <input type=\"checkbox\" name=\"read_only\" value=\"true\"" +
            readonly_checked + " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
            " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "  <span style=\"font-size:0.75rem;color:" + readonly_color +
            ";margin-left:0.5rem\">" + readonly_text + "</span>"
            "</div>";

    html += "</form>";

    html += "<p style=\"font-size:0.7rem;color:#484f58;margin-top:0.75rem\">"
            "MCP authentication uses API Tokens with an MCP tier. "
            "Create tokens in the <strong>API Tokens</strong> section above — "
            "select an MCP tier (readonly, operator, or supervised) from the dropdown."
            "</p>";

    std::string proto = cfg_->https_enabled ? "https" : "http";
    std::string host = cfg_->web_address == "0.0.0.0" ? "localhost" : cfg_->web_address;
    auto port = cfg_->https_enabled ? cfg_->https_port : cfg_->web_port;
    std::string url = proto + "://" + host + ":" + std::to_string(port) + "/mcp/v1/";

    html += "<div style=\"margin-top:0.75rem;padding:0.75rem;background:#0d1117;"
            "border:1px solid var(--border);border-radius:0.3rem\">"
            "  <div style=\"font-size:0.7rem;color:#8b949e;margin-bottom:0.3rem;"
            "font-weight:600\">MCP CLIENT CONNECTION</div>"
            "  <div style=\"font-size:0.75rem;margin-bottom:0.3rem\">"
            "    Endpoint: <code>" + html_escape(url) + "</code></div>"
            "  <div style=\"font-size:0.7rem;color:#484f58\">"
            "    Transport: HTTP + JSON-RPC 2.0 &nbsp;|&nbsp; "
            "    Auth: <code>Authorization: Bearer &lt;mcp-token&gt;</code>"
            "  </div>"
            "</div>";

    return html;
}

std::string SettingsRoutes::render_nvd_fragment() {
    std::string html;

    std::string status_color = cfg_->nvd_sync_enabled ? "#3fb950" : "#484f58";
    std::string status_text = cfg_->nvd_sync_enabled ? "Enabled" : "Disabled";

    html += "<div class=\"form-row\">"
            "  <label>NVD Sync</label>"
            "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
            status_text + "</span>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>Sync Interval</label>"
            "  <code style=\"font-size:0.8rem\">" +
            std::to_string(cfg_->nvd_sync_interval.count() / 3600) + " hours</code>"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label>API Key</label>"
            "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
            (cfg_->nvd_api_key.empty() ? std::string("Not configured (lower rate limits)") : std::string("Configured")) +
            "</span></div>";

    html += "<div class=\"form-row\">"
            "  <label>HTTP Proxy</label>"
            "  <span style=\"font-size:0.8rem\">" +
            (cfg_->nvd_proxy.empty() ? std::string("<span style=\"color:#8b949e\">None</span>") : std::string("<code>") + html_escape(cfg_->nvd_proxy) + "</code>") +
            "</span></div>";

    if (!cfg_->nvd_sync_enabled) {
        html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                "Start the server without <code>--no-nvd-sync</code> to enable CVE feed synchronization.</p>";
    }

    return html;
}

std::string SettingsRoutes::render_directory_fragment() {
    std::string html;

    bool oidc_configured = !cfg_->oidc_issuer.empty() && !cfg_->oidc_client_id.empty();

    if (oidc_configured) {
        html += "<div style=\"margin-bottom:1rem\">"
                "  <span style=\"font-size:0.75rem;background:#238636;color:#fff;"
                "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                "Configured</span>"
                "</div>";
    } else {
        html += "<div style=\"margin-bottom:1rem\">"
                "  <span style=\"font-size:0.75rem;background:#9e6a03;color:#fff;"
                "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                "Not configured</span>"
                "</div>";
    }

    html += "<form hx-post=\"/api/settings/oidc\" "
            "hx-target=\"#directory-section\" hx-swap=\"innerHTML\">";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Issuer URL</label>"
            "  <input type=\"text\" name=\"issuer\" "
            "value=\"" + html_escape(cfg_->oidc_issuer) + "\" "
            "placeholder=\"https://login.microsoftonline.com/{tenant}/v2.0\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Client ID</label>"
            "  <input type=\"text\" name=\"client_id\" "
            "value=\"" + html_escape(cfg_->oidc_client_id) + "\" "
            "placeholder=\"Application (client) ID from Azure portal\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Client Secret</label>"
            "  <input type=\"password\" name=\"client_secret\" "
            "value=\"\" "
            "placeholder=\"" +
            (cfg_->oidc_client_secret.empty()
                 ? std::string("Client secret value")
                 : std::string("********")) +
            "\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Redirect URI</label>"
            "  <input type=\"text\" name=\"redirect_uri\" "
            "value=\"" + html_escape(cfg_->oidc_redirect_uri) + "\" "
            "placeholder=\"(auto-computed from web address)\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Admin Group ID</label>"
            "  <input type=\"text\" name=\"admin_group\" "
            "value=\"" + html_escape(cfg_->oidc_admin_group) + "\" "
            "placeholder=\"Entra group object ID for admin role mapping\" "
            "style=\"flex:1;min-width:0\">"
            "</div>";

    std::string tls_checked = cfg_->oidc_skip_tls_verify ? " checked" : "";
    html += "<div class=\"form-row\">"
            "  <label style=\"min-width:140px\">Skip TLS Verify</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"checkbox\" name=\"skip_tls_verify\" value=\"true\"" +
            tls_checked +
            ">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "  <span style=\"font-size:0.7rem;color:#f85149;margin-left:0.5rem\">"
            "Insecure — dev only</span>"
            "</div>";

    html += "<div style=\"margin-top:1rem;display:flex;gap:0.75rem;align-items:center\">"
            "  <button class=\"btn btn-primary\" type=\"submit\">Save OIDC Configuration</button>"
            "  <button class=\"btn btn-secondary\" type=\"button\" "
            "hx-post=\"/api/settings/oidc/test\" "
            "hx-target=\"#oidc-feedback\" hx-swap=\"innerHTML\" "
            "hx-include=\"closest form\">Test Connection</button>"
            "</div>";

    html += "</form>";

    html += "<div class=\"feedback\" id=\"oidc-feedback\"></div>";

    return html;
}

// ── Plugin code-signing settings ────────────────────────────────────────────
//
// Storage model (intentionally minimal — see SKILL.md auth-and-authz §10
// for the full design):
//   * The PEM trust bundle lives at <cert-dir>/plugin-trust-bundle.pem.
//   * Presence of that file = "signing enabled". No separate enabled flag
//     so disk + DB cannot drift out of sync — clearing the file disables
//     signing atomically.
//   * The require flag lives in runtime_config under the
//     plugin_signing::kPluginSigningRequiredKey key.
//   * Bundle metadata (cert count, SHA-256) is recomputed from the file
//     each render rather than denormalised — keeps the source of truth
//     single (the file), at cost of a few-ms re-parse per /settings load.

namespace {

using ::yuzu::server::plugin_signing::TrustBundleStats;
using ::yuzu::server::plugin_signing::trust_bundle_path;
using ::yuzu::server::plugin_signing::validate_trust_bundle_pem;

// Read+validate the on-disk bundle (may be missing). Returns nullopt if the
// file is absent. Returns an error string if present but unreadable / parse
// failure (so the UI can surface "bundle on disk is corrupt" rather than
// silently downgrading to "no bundle").
std::optional<std::expected<TrustBundleStats, std::string>>
read_on_disk_bundle() {
    std::error_code ec;
    auto path = trust_bundle_path();
    if (!std::filesystem::exists(path, ec)) {
        return std::nullopt;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return std::expected<TrustBundleStats, std::string>(
            std::unexpect, "cannot open " + path.string());
    }
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    return validate_trust_bundle_pem(content);
}

} // namespace

std::string SettingsRoutes::render_plugin_signing_fragment() {
    std::string html;

    auto bundle = read_on_disk_bundle();
    const bool enabled = bundle && bundle->has_value();
    const bool required =
        runtime_config_store_ &&
        runtime_config_store_->get_value(plugin_signing::kPluginSigningRequiredKey) == "true";

    // Status badge
    std::string badge_color, badge_text;
    if (enabled && required) {
        badge_color = "#238636"; // green
        badge_text = "Enforced (required)";
    } else if (enabled) {
        badge_color = "#9e6a03"; // amber
        badge_text = "Trust bundle loaded (transitional)";
    } else {
        badge_color = "#484f58"; // muted
        badge_text = "Disabled";
    }
    html += "<div style=\"margin-bottom:1rem\">"
            "  <span style=\"font-size:0.75rem;background:" + badge_color +
            ";color:#fff;padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">" +
            badge_text + "</span></div>";

    // Current state
    if (enabled && bundle->has_value()) {
        const auto& stats = bundle->value();
        html += "<div class=\"form-row\"><label>Trust anchors</label>"
                "<span style=\"font-size:0.8rem\">" +
                std::to_string(stats.cert_count) + " certificate(s)</span></div>";
        html += "<div class=\"form-row\"><label>Bundle SHA-256</label>"
                "<code style=\"font-size:0.7rem;word-break:break-all\">" +
                stats.sha256_hex + "</code></div>";
        if (!stats.subjects.empty()) {
            html += "<div class=\"form-row\" style=\"align-items:flex-start\">"
                    "<label>Subjects</label>"
                    "<div style=\"font-size:0.75rem;flex:1;min-width:0\">";
            for (const auto& s : stats.subjects) {
                html += "<div style=\"font-family:monospace;color:var(--mds-color-theme-text-secondary);"
                        "overflow-wrap:anywhere\">" + html_escape(s) + "</div>";
            }
            html += "</div></div>";
        }
    } else if (bundle && !bundle->has_value()) {
        html += "<div class=\"feedback feedback-error\">Bundle on disk is unreadable: " +
                html_escape(bundle->error()) + "</div>";
    } else {
        html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "No trust bundle uploaded. Plugin signature verification is off "
                "for every agent connected to this server.</p>";
    }

    // Fleet-suicide warning: Yuzu-shipped plugins are not currently
    // signed. An operator who enables Require=on without first signing
    // the in-tree plugins will reject every Yuzu-shipped plugin
    // fleet-wide on next agent restart. Make the risk explicit before
    // they touch the toggle (governance hardening round 1, ER-1).
    html += "<div class=\"feedback feedback-warning\" "
            "style=\"font-size:0.75rem;background:#664d03;color:#fff;"
            "padding:0.5rem 0.75rem;border-radius:4px;margin-top:0.5rem\">"
            "<strong>Heads up.</strong> Yuzu-shipped plugins do not yet "
            "include CMS signatures. Enabling <em>Require signed plugins</em> "
            "will cause agents to reject every Yuzu-bundled plugin at next "
            "scan. Use the transitional mode (bundle uploaded, Require off) "
            "until you have signed every plugin your fleet uses, including "
            "the ones shipped under <code>agents/plugins/</code>."
            "</div>";

    // Upload form (multipart so curl/UI both work)
    html += "<hr style=\"border:none;border-top:1px solid var(--mds-color-theme-border-secondary);"
            "margin:1rem 0\">";
    html += "<form hx-post=\"/api/settings/plugin-signing/upload\" "
            "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
            "hx-encoding=\"multipart/form-data\">";
    html += "<div class=\"form-row\" style=\"align-items:center\">"
            "<label style=\"min-width:140px\">PEM trust bundle</label>"
            "<input type=\"file\" name=\"file\" accept=\".pem,.crt,application/x-pem-file\" "
            "required style=\"flex:1;min-width:0\"></div>";
    html += "<div class=\"form-row\"><label></label>"
            "<button type=\"submit\" class=\"btn btn-primary\">"
            "Upload &amp; verify</button></div>";
    html += "</form>";

    // Toggle: require signature (only meaningful when bundle is loaded)
    if (enabled) {
        html += "<form hx-post=\"/api/settings/plugin-signing/require\" "
                "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
                "style=\"margin-top:0.75rem\">";
        html += "<div class=\"form-row\">"
                "<label style=\"min-width:140px\">Require signed plugins</label>"
                "<label style=\"display:flex;align-items:center;gap:0.5rem;flex:1\">"
                "<input type=\"checkbox\" name=\"required\" value=\"true\"" +
                std::string(required ? " checked" : "") +
                "><span style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
                "Reject unsigned plugins instead of allowing them through (transitional vs enforced).</span>"
                "</label></div>";
        html += "<div class=\"form-row\"><label></label>"
                "<button type=\"submit\" class=\"btn btn-secondary\">Save</button></div>";
        html += "</form>";

        // Clear button — separate form so it can have a confirm.
        // Confirm copy is deliberate about what is and isn't possible
        // today: there is no automatic agent-side bundle refresh, so a
        // running agent that already loaded plugins continues to use
        // its in-process verification state. The bundle on the server
        // is removed; new agent starts (or future auto-refresh) will
        // see no bundle. Operators rotating away from a compromised CA
        // need to also restart agents (governance hardening round 1,
        // UP-5).
        html += "<form hx-post=\"/api/settings/plugin-signing/clear\" "
                "hx-target=\"#plugin-signing-section\" hx-swap=\"innerHTML\" "
                "hx-confirm=\"Remove the plugin trust bundle and reset the require flag? "
                "This stops new agent starts from verifying signatures, but already-running "
                "agents keep their in-process state until they restart. "
                "If you are rotating away from a compromised CA, restart your agents.\" "
                "style=\"margin-top:0.75rem\">";
        html += "<div class=\"form-row\"><label></label>"
                "<button type=\"submit\" class=\"btn btn-danger\">Remove trust bundle</button>"
                "</div></form>";
    }

    // Operator help
    html += "<hr style=\"border:none;border-top:1px solid var(--mds-color-theme-border-secondary);"
            "margin:1rem 0\">";
    html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary);"
            "margin-bottom:0.4rem\"><strong>Agent distribution.</strong> The bundle "
            "is served at <code>GET /api/v1/agent/plugin-policy</code> "
            "(<em>admin-only</em> — operators distribute to agents via the "
            "standard config-management flow). Agents are pointed at a local "
            "file via <code>--plugin-trust-bundle</code>; automatic agent-side "
            "fetch is a forthcoming change, at which point this endpoint will "
            "gain a dedicated agent identity.</p>";
    html += "<p style=\"font-size:0.75rem;color:var(--mds-color-theme-text-tertiary)\">"
            "<strong>Signing recipe:</strong> "
            "<code>openssl cms -sign -binary -nodetach=false -signer signer.pem "
            "-inkey signer.key -in plugin.so -outform pem -out plugin.so.sig</code>. "
            "See <a href=\"/docs#plugin-code-signing\">user manual</a> for the full workflow.</p>";

    return html;
}

// ── Route registration ──────────────────────────────────────────────────────

// Production overload — wraps httplib::Server in an HttplibRouteSink and
// delegates to the sink-based implementation below. Tests bypass this and
// call the sink overload directly with their own TestRouteSink (#438).
void SettingsRoutes::register_routes(httplib::Server& svr,
                                      AuthFn auth_fn,
                                      AdminFn admin_fn,
                                      PermFn perm_fn,
                                      AuditFn audit_fn,
                                      Config& cfg,
                                      auth::AuthManager& auth_mgr,
                                      auth::AutoApproveEngine& auto_approve,
                                      ApiTokenStore* api_token_store,
                                      ManagementGroupStore* mgmt_group_store,
                                      TagStore* tag_store,
                                      UpdateRegistry* update_registry,
                                      RuntimeConfigStore* runtime_config_store,
                                      AuditStore* audit_store,
                                      bool gateway_enabled,
                                      GatewaySessionCountFn gateway_session_count_fn,
                                      AgentsJsonFn agents_json_fn,
                                      std::shared_mutex& oidc_mu,
                                      std::unique_ptr<oidc::OidcProvider>& oidc_provider) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(admin_fn), std::move(perm_fn),
                    std::move(audit_fn), cfg, auth_mgr, auto_approve, api_token_store,
                    mgmt_group_store, tag_store, update_registry, runtime_config_store,
                    audit_store, gateway_enabled, std::move(gateway_session_count_fn),
                    std::move(agents_json_fn), oidc_mu, oidc_provider);
}

void SettingsRoutes::register_routes(HttpRouteSink& sink,
                                      AuthFn auth_fn,
                                      AdminFn admin_fn,
                                      PermFn perm_fn,
                                      AuditFn audit_fn,
                                      Config& cfg,
                                      auth::AuthManager& auth_mgr,
                                      auth::AutoApproveEngine& auto_approve,
                                      ApiTokenStore* api_token_store,
                                      ManagementGroupStore* mgmt_group_store,
                                      TagStore* tag_store,
                                      UpdateRegistry* update_registry,
                                      RuntimeConfigStore* runtime_config_store,
                                      AuditStore* audit_store,
                                      bool gateway_enabled,
                                      GatewaySessionCountFn gateway_session_count_fn,
                                      AgentsJsonFn agents_json_fn,
                                      std::shared_mutex& oidc_mu,
                                      std::unique_ptr<oidc::OidcProvider>& oidc_provider) {
    // Store dependency pointers
    auth_fn_ = std::move(auth_fn);
    admin_fn_ = std::move(admin_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    cfg_ = &cfg;
    auth_mgr_ = &auth_mgr;
    auto_approve_ = &auto_approve;
    api_token_store_ = api_token_store;
    mgmt_group_store_ = mgmt_group_store;
    tag_store_ = tag_store;
    update_registry_ = update_registry;
    runtime_config_store_ = runtime_config_store;
    audit_store_ = audit_store;
    gateway_enabled_ = gateway_enabled;
    gateway_session_count_fn_ = std::move(gateway_session_count_fn);
    agents_json_fn_ = std::move(agents_json_fn);
    oidc_mu_ = &oidc_mu;
    oidc_provider_ = &oidc_provider;

    // -- Settings page (admin only) -------------------------------------------
    sink.Get("/settings", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_content(kSettingsHtml, "text/html; charset=utf-8");
    });

    // -- Settings HTMX fragment endpoints -------------------------------------

    sink.Get("/fragments/settings/tls",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/users",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                auto session = auth_fn_(req, res);
                if (!session) {
                    // Match the DELETE handler's defensive branch: if
                    // admin_fn_ passes but auth_fn_ returns nullopt the
                    // two callbacks have disagreed (concurrent logout,
                    // stale cookie, OIDC session expiry between calls).
                    // Refuse to render with empty self_name — that path
                    // would emit Remove buttons on every row including
                    // the operator's own, resurrecting #403 inside the
                    // dashboard fragment.
                    res.status = 401;
                    return;
                }
                if (session->username.empty()) {
                    // Defense-in-depth against an upstream auth bug
                    // (e.g. OIDC mis-config returning empty
                    // preferred_username). Empty session->username would
                    // make the is_self comparison in render_users_fragment
                    // never match any row, and would also let a hand-
                    // crafted DELETE against an empty-username row
                    // succeed via "" == "" — see governance Gate 4 UP-1.
                    spdlog::error("/fragments/settings/users: session has empty username; "
                                  "refusing to render (likely upstream auth misconfiguration)");
                    res.status = 500;
                    return;
                }
                res.set_content(render_users_fragment(session->username),
                                "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/tokens",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/pending",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/auto-approve",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/api-tokens",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "ApiToken", "Read"))
                    return;
                auto session = auth_fn_(req, res);
                if (!session)
                    return;
                // Non-admins see only their own tokens (Gate 4 finding C1).
                std::string filter = session->role == auth::Role::admin
                                         ? std::string{}
                                         : session->username;
                res.set_content(render_api_tokens_fragment({}, filter),
                                "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/management-groups",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "ManagementGroup", "Read"))
                    return;
                res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/tag-compliance",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Tag", "Read"))
                    return;
                res.set_content(render_tag_compliance_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/updates",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/gateway",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_gateway_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/server-config",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_server_config_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/https",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_https_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/analytics",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_analytics_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/data-retention",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_data_retention_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/mcp",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_mcp_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/plugin-signing",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_plugin_signing_fragment(),
                                "text/html; charset=utf-8");
            });

    // -- Plugin Code Signing: upload PEM trust bundle (admin) -----------------
    sink.Post("/api/settings/plugin-signing/upload",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;

                  std::string content;
                  if (SETTINGS_REQ_HAS_FILE(req, "file")) {
                      content = SETTINGS_REQ_GET_FILE(req, "file").content;
                  }
                  if (content.empty()) {
                      res.status = 400;
                      res.set_header("HX-Retarget", "#plugin-signing-section");
                      res.set_content(
                          "<span class=\"feedback-error\">Upload a PEM file.</span>",
                          "text/html; charset=utf-8");
                      return;
                  }
                  if (content.size() > 256 * 1024) {
                      res.status = 400;
                      res.set_header("HX-Retarget", "#plugin-signing-section");
                      res.set_content(
                          "<span class=\"feedback-error\">PEM bundle too large (max 256 KB).</span>",
                          "text/html; charset=utf-8");
                      return;
                  }

                  auto stats = validate_trust_bundle_pem(content);
                  if (!stats) {
                      res.status = 400;
                      res.set_header("HX-Retarget", "#plugin-signing-section");
                      res.set_content(
                          "<span class=\"feedback-error\">Rejected: " +
                              html_escape(stats.error()) + "</span>",
                          "text/html; charset=utf-8");
                      // result="failure" — PEM validation rejected the operator's input.
                      // Vocabulary: success/failure/denied per audit_store.hpp:28.
                      // ("rejected" was a novel token that silently undercounts
                      // the Prometheus events_other_ bucket — fixed in
                      // governance hardening round 1, arch-B1 / CONS-B2 / CC7.2.)
                      audit_fn_(req, "plugin_signing.bundle.uploaded", "failure",
                                "PluginTrustBundle", "trust-bundle", stats.error());
                      return;
                  }

                  auto cert_dir = auth::default_cert_dir();
                  std::error_code ec;
                  std::filesystem::create_directories(cert_dir, ec);
                  if (ec) {
                      res.status = 500;
                      res.set_header("HX-Retarget", "#plugin-signing-section");
                      res.set_content(
                          "<span class=\"feedback-error\">Cannot create cert directory.</span>",
                          "text/html; charset=utf-8");
                      return;
                  }
                  // Atomic write: stage in a sibling temp file, then rename
                  // over the destination. Same-directory rename is
                  // POSIX-atomic and Windows-replace-atomic via MoveFileExW.
                  // Prevents the torn-read window where a concurrent
                  // /api/v1/agent/plugin-policy fetch reads a 0-byte or
                  // partial PEM mid-write (sec-MED-1 / UP-1 / UP-2 / UP-16
                  // / hp-S1).
                  auto out_path = trust_bundle_path();
                  auto tmp_path = out_path;
                  tmp_path += ".tmp";
                  {
                      std::ofstream f(tmp_path,
                                      std::ios::binary | std::ios::trunc);
                      if (!f.is_open()) {
                          res.status = 500;
                          res.set_header("HX-Retarget", "#plugin-signing-section");
                          res.set_content(
                              "<span class=\"feedback-error\">Cannot write trust bundle file.</span>",
                              "text/html; charset=utf-8");
                          return;
                      }
                      f.write(content.data(),
                              static_cast<std::streamsize>(content.size()));
                      f.flush();
                      // Surface short-write / disk-full / EIO before we
                      // attempt the atomic rename. Without this, a partial
                      // tmp file would be renamed into place and the
                      // operator would see "uploaded" while agents see
                      // a corrupt bundle (hp-S1 / UP-16).
                      if (!f.good()) {
                          std::error_code rmec;
                          std::filesystem::remove(tmp_path, rmec);
                          res.status = 500;
                          res.set_header("HX-Retarget", "#plugin-signing-section");
                          res.set_content(
                              "<span class=\"feedback-error\">Trust bundle write failed (disk full?).</span>",
                              "text/html; charset=utf-8");
                          return;
                      }
                  }
                  std::error_code rnec;
                  std::filesystem::rename(tmp_path, out_path, rnec);
                  if (rnec) {
                      std::error_code rmec;
                      std::filesystem::remove(tmp_path, rmec);
                      res.status = 500;
                      res.set_header("HX-Retarget", "#plugin-signing-section");
                      res.set_content(
                          "<span class=\"feedback-error\">Atomic rename of trust bundle failed: " +
                              html_escape(rnec.message()) + "</span>",
                          "text/html; charset=utf-8");
                      return;
                  }
                  // Trust bundles are public-readable (only contains
                  // X.509 certs, no private keys).

                  spdlog::info("Plugin trust bundle uploaded: {} ({} certs, sha256 {})",
                               out_path.string(), stats->cert_count, stats->sha256_hex);
                  audit_fn_(req, "plugin_signing.bundle.uploaded", "success",
                            "PluginTrustBundle", "trust-bundle",
                            std::to_string(stats->cert_count) + " cert(s), sha256=" +
                                stats->sha256_hex);

                  res.set_header("HX-Trigger",
                      R"({"showToast":{"message":"Trust bundle uploaded","level":"success"}})");
                  res.set_content(render_plugin_signing_fragment(),
                                  "text/html; charset=utf-8");
              });

    // -- Plugin Code Signing: clear trust bundle (admin) ----------------------
    sink.Post("/api/settings/plugin-signing/clear",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;

                  // Two-phase commit: clear the DB flag FIRST, then remove
                  // the file. If the flag write fails we surface a 500 and
                  // never touch the file — agents continue to verify
                  // against the existing bundle and the operator sees an
                  // explicit error rather than a silent "file gone but
                  // require still on" state (UP-4).
                  if (runtime_config_store_) {
                      auto rc = runtime_config_store_->set(
                          plugin_signing::kPluginSigningRequiredKey, "false", "system");
                      if (!rc) {
                          res.status = 500;
                          res.set_header("HX-Retarget",
                                         "#plugin-signing-section");
                          res.set_content(
                              "<span class=\"feedback-error\">Cannot clear "
                              "require flag: " + html_escape(rc.error()) +
                                  ". Trust bundle was not removed.</span>",
                              "text/html; charset=utf-8");
                          audit_fn_(req, "plugin_signing.bundle.cleared",
                                    "failure", "PluginTrustBundle",
                                    "trust-bundle",
                                    "require-flag write failed: " + rc.error());
                          return;
                      }
                  }
                  auto path = trust_bundle_path();
                  std::error_code ec;
                  bool removed = std::filesystem::remove(path, ec);

                  spdlog::info(
                      "Plugin trust bundle cleared (file {}, require flag reset)",
                      removed ? "removed" : "absent");
                  audit_fn_(req, "plugin_signing.bundle.cleared", "success",
                            "PluginTrustBundle", "trust-bundle",
                            removed ? "file removed" : "no file present");

                  res.set_header("HX-Trigger",
                      R"({"showToast":{"message":"Trust bundle cleared","level":"info"}})");
                  res.set_content(render_plugin_signing_fragment(),
                                  "text/html; charset=utf-8");
              });

    // -- Plugin Code Signing: toggle require flag (admin) ---------------------
    sink.Post("/api/settings/plugin-signing/require",
              [this](const httplib::Request& req, httplib::Response& res) {
                  if (!admin_fn_(req, res))
                      return;
                  // HTML checkbox semantics: present-and-"true" = required;
                  // absent = not required. Reuse the form parser the rest
                  // of settings uses.
                  const std::string val =
                      extract_form_value(req.body, "required");
                  const std::string new_val =
                      (val == "true" || val == "on") ? "true" : "false";
                  if (runtime_config_store_) {
                      auto rc = runtime_config_store_->set(
                          plugin_signing::kPluginSigningRequiredKey, new_val, "ui");
                      if (!rc) {
                          res.status = 500;
                          res.set_header("HX-Retarget",
                                         "#plugin-signing-section");
                          res.set_content("<span class=\"feedback-error\">" +
                                              html_escape(rc.error()) +
                                              "</span>",
                                          "text/html; charset=utf-8");
                          return;
                      }
                  }
                  audit_fn_(req, "plugin_signing.require.changed", "success",
                            "RuntimeConfig", plugin_signing::kPluginSigningRequiredKey, new_val);
                  res.set_header(
                      "HX-Trigger",
                      R"({"showToast":{"message":"Require flag updated","level":"success"}})");
                  res.set_content(render_plugin_signing_fragment(),
                                  "text/html; charset=utf-8");
              });

    // -- Plugin Code Signing: distribution endpoint --------------------------
    //
    // Returns the current trust bundle and require flag as JSON for
    // out-of-band distribution to agents (operators curl this into
    // /etc/yuzu/plugin-trust-bundle.pem on each agent host, then pass
    // --plugin-trust-bundle to the agent). Future automatic agent-side
    // fetch will use the same shape.
    //
    // Authorization: admin only. The bundle PEM holds X.509 certificates
    // (no private keys) so the security blast radius of disclosure is
    // small, but a non-admin token holder learning when the trust anchor
    // rotates (sha256 changes) is useful reconnaissance for a
    // supply-chain attacker. CC6.1 least-privilege requires we restrict
    // even read access to security-critical config to admin principals
    // (governance hardening round 1: sec-LOW-4 / UP-13 / CC6.1).
    sink.Get("/api/v1/agent/plugin-policy",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res)) return;

                 auto disk = read_on_disk_bundle();
                 const bool required =
                     runtime_config_store_ &&
                     runtime_config_store_->get_value(
                         plugin_signing::kPluginSigningRequiredKey) == "true";

                 // Bundle absent → 200 success-shape with enabled=false.
                 // Status code 404 was misleading: "no bundle uploaded" is
                 // a normal operational state, not a fetch failure
                 // (CONS-B1 part 2).
                 if (!disk) {
                     nlohmann::json out;
                     out["enabled"] = false;
                     out["required"] = required;
                     out["trust_bundle_pem"] = "";
                     res.set_content(out.dump(), "application/json");
                     return;
                 }
                 if (!disk->has_value()) {
                     // Structured envelope (A4 / CONS-B1) — same shape as
                     // every other /api/v1/* error site (auth_routes,
                     // rest_api_v1, etc.).
                     res.status = 500;
                     nlohmann::json err = {
                         {"error",
                          {{"code", 500},
                           {"message", "Trust bundle on disk is unreadable"}}},
                         {"meta", {{"api_version", "v1"}}}};
                     res.set_content(err.dump(), "application/json");
                     return;
                 }

                 // Re-read the file so the response carries the actual
                 // bytes, not a regenerated copy.
                 std::ifstream f(trust_bundle_path(), std::ios::binary);
                 std::string pem((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
                 nlohmann::json out;
                 out["enabled"] = true;
                 out["required"] = required;
                 out["trust_bundle_pem"] = pem;
                 out["cert_count"] = disk->value().cert_count;
                 out["sha256"] = disk->value().sha256_hex;
                 res.set_content(out.dump(), "application/json");
             });

    sink.Get("/fragments/settings/nvd",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_nvd_fragment(), "text/html; charset=utf-8");
            });

    sink.Get("/fragments/settings/directory",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!admin_fn_(req, res))
                    return;
                res.set_content(render_directory_fragment(), "text/html; charset=utf-8");
            });

    // -- Settings API: TLS toggle (HTMX POST) ---------------------------------
    sink.Post("/api/settings/tls",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 auto val = extract_form_value(req.body, "tls_enabled");
                 cfg_->tls_enabled = (val == "true");
                 spdlog::info("TLS setting changed to {} (restart required)",
                              cfg_->tls_enabled ? "enabled" : "disabled");
                 res.set_header("HX-Retarget", "#tls-section");
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"TLS settings saved","level":"success"}})");
                 res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
             });

    // -- Settings API: Certificate upload (admin only, multipart) --------------
    sink.Post("/api/settings/cert-upload", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        std::string type;
        std::string content;

        if (req.has_param("type")) {
            type = req.get_param_value("type");
        }

        if (SETTINGS_REQ_HAS_FILE(req, "file")) {
            content = SETTINGS_REQ_GET_FILE(req, "file").content;
        }

        if (type.empty() || content.empty()) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Type and file are required.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        auto cert_dir = auth::default_cert_dir();
        std::error_code ec;
        std::filesystem::create_directories(cert_dir, ec);
        if (ec) {
            res.status = 500;
            res.set_content(
                "<span class=\"feedback-error\">Cannot create cert directory.</span>",
                "text/html; charset=utf-8");
            return;
        }

        std::string out_name;
        if (type == "cert")
            out_name = "server.pem";
        else if (type == "key")
            out_name = "server-key.pem";
        else if (type == "ca")
            out_name = "ca.pem";
        else {
            res.status = 400;
            res.set_content(
                "<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                "text/html; charset=utf-8");
            return;
        }

        auto out_path = cert_dir / out_name;
        {
            std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_content("<span class=\"feedback-error\">Cannot write cert file.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

        if (type == "cert")
            cfg_->tls_server_cert = out_path;
        else if (type == "key")
            cfg_->tls_server_key = out_path;
        else if (type == "ca")
            cfg_->tls_ca_cert = out_path;

#ifndef _WIN32
        if (type == "key") {
            std::filesystem::permissions(out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        }
#endif

        spdlog::info("Certificate uploaded: {} -> {}", type, out_path.string());
        audit_fn_(req, "cert.upload", "success", "Certificate", type, "");

        res.set_header("HX-Retarget", "#tls-section");
        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"Certificate uploaded","level":"success"}})");
        res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: Paste PEM content (admin only, HTMX) --------------------
    sink.Post("/api/settings/cert-paste", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto type = extract_form_value(req.body, "type");
        auto content = extract_form_value(req.body, "content");

        if (type.empty() || content.empty()) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content("<span class=\"feedback-error\">Type and PEM content are required.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        if (content.size() > 65536) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content(
                "<span class=\"feedback-error\">PEM content too large (max 64 KB).</span>",
                "text/html; charset=utf-8");
            return;
        }

        if (content.find("-----BEGIN") == std::string::npos ||
            content.find("-----END") == std::string::npos) {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content(
                "<span class=\"feedback-error\">Invalid PEM: must contain -----BEGIN and -----END markers.</span>",
                "text/html; charset=utf-8");
            return;
        }

        std::erase(content, '\r');

        std::string out_name;
        if (type == "cert")
            out_name = "server.pem";
        else if (type == "key")
            out_name = "server-key.pem";
        else if (type == "ca")
            out_name = "ca.pem";
        else {
            res.status = 400;
            res.set_header("HX-Retarget", "#tls-section");
            res.set_content(
                "<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                "text/html; charset=utf-8");
            return;
        }

        auto cert_dir = auth::default_cert_dir();
        std::error_code ec;
        std::filesystem::create_directories(cert_dir, ec);
        if (ec) {
            res.status = 500;
            res.set_content(
                "<span class=\"feedback-error\">Cannot create cert directory.</span>",
                "text/html; charset=utf-8");
            return;
        }

        auto out_path = cert_dir / out_name;
        {
            std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_content("<span class=\"feedback-error\">Cannot write cert file.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

#ifndef _WIN32
        if (type == "key") {
            std::filesystem::permissions(out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        }
#endif

        if (type == "cert")
            cfg_->tls_server_cert = out_path;
        else if (type == "key")
            cfg_->tls_server_key = out_path;
        else if (type == "ca")
            cfg_->tls_ca_cert = out_path;

        spdlog::info("Certificate pasted: {} -> {}", type, out_path.string());
        audit_fn_(req, "cert.paste", "success", "Certificate", type, "");

        res.set_header("HX-Retarget", "#tls-section");
        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"Certificate saved from paste","level":"success"}})");
        res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: OIDC configuration (admin only, HTMX) -------------------
    sink.Post("/api/settings/oidc", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto issuer = extract_form_value(req.body, "issuer");
        auto client_id = extract_form_value(req.body, "client_id");
        auto client_secret = extract_form_value(req.body, "client_secret");
        auto redirect_uri = extract_form_value(req.body, "redirect_uri");
        auto admin_group = extract_form_value(req.body, "admin_group");
        auto skip_tls_verify = extract_form_value(req.body, "skip_tls_verify");

        if (issuer.empty() || client_id.empty()) {
            res.status = 400;
            auto html = render_directory_fragment() +
                "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                "hx-swap-oob=\"true\">Issuer URL and Client ID are required.</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        auto effective_secret = client_secret.empty() ? cfg_->oidc_client_secret : client_secret;
        bool skip_tls = (skip_tls_verify == "true");

        std::unique_ptr<oidc::OidcProvider> new_provider;
        try {
            oidc::OidcConfig oidc_cfg;
            oidc_cfg.issuer = issuer;
            oidc_cfg.client_id = client_id;
            oidc_cfg.client_secret = effective_secret;
            oidc_cfg.redirect_uri = redirect_uri;
            oidc_cfg.admin_group_id = admin_group;
            oidc_cfg.skip_tls_verify = skip_tls;
            if (skip_tls)
                spdlog::warn("OIDC TLS certificate verification DISABLED — do not use in production");

            auto v2_pos = issuer.rfind("/v2.0");
            if (v2_pos != std::string::npos) {
                auto base = issuer.substr(0, v2_pos);
                oidc_cfg.authorization_endpoint = base + "/oauth2/v2.0/authorize";
                oidc_cfg.token_endpoint = base + "/oauth2/v2.0/token";
            } else {
                oidc_cfg.authorization_endpoint = issuer + "/authorize";
                oidc_cfg.token_endpoint = issuer + "/token";
            }

            auto src_script =
                std::filesystem::current_path() / "scripts" / "oidc_token_exchange.py";
            if (std::filesystem::exists(src_script))
                oidc_cfg.exchange_script = src_script.string();

            new_provider = std::make_unique<oidc::OidcProvider>(std::move(oidc_cfg));
        } catch (const std::exception& e) {
            spdlog::error("OIDC provider reinit failed: {}", e.what());
            res.status = 500;
            auto html = render_directory_fragment() +
                "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                "hx-swap-oob=\"true\">OIDC init failed: " + html_escape(e.what()) + "</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        {
            std::unique_lock lock(*oidc_mu_);
            cfg_->oidc_issuer = issuer;
            cfg_->oidc_client_id = client_id;
            cfg_->oidc_client_secret = effective_secret;
            cfg_->oidc_redirect_uri = redirect_uri;
            cfg_->oidc_admin_group = admin_group;
            cfg_->oidc_skip_tls_verify = skip_tls;
            *oidc_provider_ = std::move(new_provider);
        }
        spdlog::info("OIDC provider reinitialized via Settings UI (issuer={})", issuer);

        if (runtime_config_store_ && runtime_config_store_->is_open()) {
            auto who = std::string("admin");
            auto session = auth_fn_(req, res);
            if (session) who = session->username;
            runtime_config_store_->set("oidc_issuer", issuer, who);
            runtime_config_store_->set("oidc_client_id", client_id, who);
            if (!client_secret.empty())
                runtime_config_store_->set("oidc_client_secret", client_secret, who);
            runtime_config_store_->set("oidc_redirect_uri", redirect_uri, who);
            runtime_config_store_->set("oidc_admin_group", admin_group, who);
            runtime_config_store_->set("oidc_skip_tls_verify", skip_tls ? "true" : "false", who);
        }

        audit_fn_(req, "oidc.configure", "success", "OidcConfig", issuer, "");

        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"OIDC configuration saved","level":"success"}})");
        res.set_content(render_directory_fragment(), "text/html; charset=utf-8");
    });

    // -- Settings API: OIDC test connection (admin only, HTMX) -----------------
    sink.Post("/api/settings/oidc/test", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;

        auto issuer = extract_form_value(req.body, "issuer");
        auto skip_tls_str = extract_form_value(req.body, "skip_tls_verify");
        bool skip_tls = (skip_tls_str == "true") || cfg_->oidc_skip_tls_verify;

        if (issuer.empty())
            issuer = cfg_->oidc_issuer;

        if (issuer.empty()) {
            res.set_content(
                "<span class=\"feedback-error\">Enter an Issuer URL first.</span>",
                "text/html; charset=utf-8");
            return;
        }

        auto discovery_url = issuer;
        if (!discovery_url.ends_with("/"))
            discovery_url += "/";
        discovery_url += ".well-known/openid-configuration";

        audit_fn_(req, "oidc.test", "attempt", "OidcConfig", issuer, "");

        try {
            std::string url = discovery_url;
            std::string scheme;
            if (url.starts_with("https://")) {
                scheme = "https://";
                url = url.substr(8);
            } else if (url.starts_with("http://")) {
                scheme = "http://";
                url = url.substr(7);
            } else {
                res.set_content(
                    "<span class=\"feedback-error\">Invalid issuer URL scheme (must be http or https).</span>",
                    "text/html; charset=utf-8");
                return;
            }
            auto slash = url.find('/');
            auto host = (slash != std::string::npos) ? url.substr(0, slash) : url;
            auto path = (slash != std::string::npos) ? url.substr(slash) : "/";

            auto client = std::make_unique<httplib::Client>(scheme + host);
            client->set_connection_timeout(10);
            client->set_read_timeout(10);
            client->enable_server_certificate_verification(!skip_tls);

            auto result = client->Get(path);

            int status_code = result ? result->status : 0;
            std::string body_copy = result ? result->body : "";
            std::string err_str = result ? "" : httplib::to_string(result.error());
            client.reset();

            if (status_code == 200) {
                auto j = nlohmann::json::parse(body_copy);
                std::string auth_ep = j.value("authorization_endpoint", "");
                std::string token_ep = j.value("token_endpoint", "");
                if (!auth_ep.empty() && !token_ep.empty()) {
                    res.set_content(
                        "<span class=\"feedback-ok\" style=\"color:#3fb950;font-size:0.8rem\">"
                        "Connected &#x2014; discovered authorization and token endpoints</span>",
                        "text/html; charset=utf-8");
                } else {
                    res.set_content(
                        "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                        "Discovery succeeded but missing authorization/token endpoints.</span>",
                        "text/html; charset=utf-8");
                }
            } else if (status_code == 0) {
                res.set_content(
                    "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                    "Discovery failed: " + html_escape(err_str) + "</span>",
                    "text/html; charset=utf-8");
            } else {
                res.set_content(
                    "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                    "Discovery failed: HTTP " + std::to_string(status_code) + "</span>",
                    "text/html; charset=utf-8");
            }
        } catch (const nlohmann::json::exception& e) {
            res.set_content(
                "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                "Discovery response is not valid JSON: " + html_escape(e.what()) + "</span>",
                "text/html; charset=utf-8");
        } catch (const std::exception& e) {
            res.set_content(
                "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                "Discovery failed: " + html_escape(e.what()) + "</span>",
                "text/html; charset=utf-8");
        }
    });

    // -- Settings API: User management (admin only, HTMX) ----------------------
    sink.Post("/api/settings/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            // Match DELETE defensive branch — see GET handler comment.
            res.status = 401;
            return;
        }
        if (session->username.empty()) {
            spdlog::error("POST /api/settings/users: session has empty username; "
                          "refusing to upsert (likely upstream auth misconfiguration)");
            res.status = 500;
            return;
        }
        auto username = extract_form_value(req.body, "username");
        auto password = extract_form_value(req.body, "password");

        // C1 FIX: Role parameter is IGNORED on user creation.
        // New users are ALWAYS created as 'user' role. To change a user's
        // role, use the dedicated POST /api/settings/users/:username/role
        // endpoint (enhanced audit logging, session invalidation).
        // This prevents privilege escalation where a compromised admin
        // silently creates additional admin accounts.
        auth::Role role = auth::Role::user;

        if (username.empty() || password.empty()) {
            res.status = 400;
            res.set_content(render_users_fragment(session->username) +
                                "<script>document.getElementById('user-feedback')."
                                "className='feedback feedback-error';"
                                "document.getElementById('user-feedback').textContent='"
                                "Username and password required.';</script>",
                            "text/html; charset=utf-8");
            return;
        }

        // H1 FIX: Validate username format (alphanumeric + ._- only, no ':')
        if (!is_valid_username(username)) {
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username: must be 1-64 chars, alphanumeric + ._- only","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // #399: reject duplicate username on the create path.
        if (auth_mgr_->get_user_role(username).has_value()) {
            spdlog::warn("POST /api/settings/users: username '{}' already exists — rejected", username);
            audit_fn_(req, "user.create", "denied", "User", username, "duplicate_username");
            res.status = 409;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Username already exists","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }
        // C1 FIX: Self-password-change is allowed, but role is always 'user' on creation.
        // Role changes must go through POST /api/settings/users/:username/role.
        // The self-demotion guard is no longer needed on this path since
        // new users are always created as 'user' role.
        if (!auth_mgr_->upsert_user(username, password, role)) {
            spdlog::warn("POST /api/settings/users: upsert rejected for '{}' "
                         "(weak_password — minimum 12 characters)",
                         username);
            audit_fn_(req, "user.create", "denied", "User", username, "weak_password");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Password must be at least 12 characters","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }
        if (!auth_mgr_->save_config()) {
            spdlog::error("Failed to save config after user create");
        }
        std::string role_str = auth::role_to_string(role);
        spdlog::info("User '{}' created (role={})", username, role_str);
        // SOC 2 CC7.2: privileged user lifecycle operations must appear
        // in audit_store, not just spdlog (governance Gate 6 CO-1).
        audit_fn_(req, "user.create", "success", "User", username, "role=" + role_str);
        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"User created","level":"success"}})");
        res.set_content(render_users_fragment(session->username), "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/users/(.+))", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            // admin_fn_ already authenticated the caller; this branch is
            // defensive — if the two callbacks disagree there is a deeper
            // bug and we refuse to proceed rather than delete on a stale
            // or unresolvable session.
            res.status = 401;
            return;
        }
        if (session->username.empty()) {
            // Defense-in-depth: an empty session->username would let
            // a hand-crafted DELETE against an empty-username row
            // succeed via the "" == "" comparison below. The root
            // cause of empty session->username is upstream (typically
            // OIDC mis-config returning empty preferred_username), but
            // the handler fails closed regardless. Governance Gate 4 UP-1.
            spdlog::error("DELETE /api/settings/users: session has empty username; "
                          "refusing to delete (likely upstream auth misconfiguration)");
            res.status = 500;
            return;
        }
        auto username = req.matches[1].str();
        // Username allowlist before any state mutation. Without this a
        // hand-crafted DELETE against `..%2Ffoo` or characters that
        // bypass URL canonicalisation reaches remove_user() with bytes
        // that should never have entered the user-store path.
        if (!is_valid_username(username)) {
            audit_fn_(req, "user.delete", "denied", "User", username, "invalid_username");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username format","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }
        // Self-deletion lockout guard (#397). Deleting the currently
        // authenticated operator — typically the sole admin on a single-
        // seat deployment — leaves the running server with zero usable
        // credentials until it is restarted against its on-disk config.
        // The UI suppresses the Remove button for the self row (#403),
        // but the handler must reject independently because a hand-
        // crafted HTTP DELETE bypasses the dashboard entirely.
        if (username == session->username) {
            spdlog::warn("User '{}' attempted to delete their own account via "
                         "/api/settings/users — rejected",
                         session->username);
            // SOC 2 CC7.2: rejected privileged operations must appear
            // in audit_store, not just spdlog (governance Gate 6 CO-1).
            // SIEM ingestion paths read audit events; spdlog rotation
            // alone is not the evidence chain.
            audit_fn_(req, "user.delete", "denied", "User", username, "self_delete_blocked");
            res.status = 403;
            // Toast wording must stay in sync with docs/user-manual/server-admin.md
            // and the CHANGELOG Fixed entry — operators search both.
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Cannot delete your own account","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }
        if (auth_mgr_->remove_user(username)) {
            if (!auth_mgr_->save_config()) {
                spdlog::error("Failed to save config after user removal");
            }
            spdlog::info("User '{}' removed", username);
            audit_fn_(req, "user.delete", "success", "User", username, "");
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"User deleted","level":"success"}})");
        } else {
            // remove_user() returns false when the username is not in the
            // user store. A no-op DELETE is still a privileged-mutation
            // attempt and must surface in the audit chain.
            audit_fn_(req, "user.delete", "denied", "User", username, "user_not_found");
            res.status = 404;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"User not found","level":"error"}})");
        }
        res.set_content(render_users_fragment(session->username),
                        "text/html; charset=utf-8");
    });

    // -- Settings API: Role change (admin only, C1 fix) -------------------------
    // Dedicated endpoint for changing user roles. Separated from user creation
    // to enforce enhanced audit logging and session invalidation.
    sink.Post(R"(/api/settings/users/(.+)/role)", [this](const httplib::Request& req,
                                                           httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            return;
        }
        if (session->username.empty()) {
            spdlog::error("POST /api/settings/users/:username/role: session has empty username");
            res.status = 500;
            return;
        }
        auto target_username = req.matches[1].str();

        // H1 FIX: Validate username in path parameter
        if (!is_valid_username(target_username)) {
            // SOC 2 CC7.2: every denied branch on a privileged-mutation
            // endpoint emits an audit event so the SIEM evidence chain is
            // complete (governance PR4 audit-coverage).
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "invalid_username");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid username format","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Self-demotion guard — can't change your own role
        if (target_username == session->username) {
            spdlog::warn("User '{}' attempted to change their own role via "
                         "/api/settings/users/:username/role — rejected",
                         session->username);
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "self_role_change_blocked");
            res.status = 403;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Cannot change your own role","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Parse requested role from JSON body
        std::string requested_role;
        try {
            auto json = nlohmann::json::parse(req.body);
            if (!json.contains("role") || !json["role"].is_string()) {
                audit_fn_(req, "user.role_change", "denied", "User", target_username,
                          "missing_role");
                res.status = 400;
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Missing or invalid 'role' field","level":"error"}})");
                res.set_content(render_users_fragment(session->username),
                                "text/html; charset=utf-8");
                return;
            }
            requested_role = json["role"].get<std::string>();
        } catch (const std::exception& e) {
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "invalid_json");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid JSON body","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Allowlist check — only 'admin' or 'user' allowed
        auth::Role new_role;
        if (requested_role == "admin") {
            new_role = auth::Role::admin;
        } else if (requested_role == "user") {
            new_role = auth::Role::user;
        } else {
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "invalid_role");
            res.status = 400;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Invalid role: must be 'admin' or 'user'","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Get current role for audit logging
        auto current_entry_opt = auth_mgr_->get_user_role(target_username);
        if (!current_entry_opt) {
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "user_not_found");
            res.status = 404;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"User not found","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }
        auth::Role old_role = *current_entry_opt;

        // No-op if role unchanged
        if (old_role == new_role) {
            // No state change, but audit the operator's intent — distinguishes
            // "tried to set already-current role" from "no request was made"
            // for compliance review.
            audit_fn_(req, "user.role_change", "no_op", "User", target_username,
                      "same_role=" + auth::role_to_string(new_role));
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Role unchanged","level":"info"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Perform role change (AuthManager.update_role() handles DB + session invalidation)
        if (!auth_mgr_->update_role(target_username, new_role)) {
            spdlog::error("Failed to update role for '{}'", target_username);
            audit_fn_(req, "user.role_change", "denied", "User", target_username,
                      "db_failure");
            res.status = 500;
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Failed to update role","level":"error"}})");
            res.set_content(render_users_fragment(session->username),
                            "text/html; charset=utf-8");
            return;
        }

        // Enhanced audit logging (C1 requirement)
        std::string old_role_str = auth::role_to_string(old_role);
        std::string new_role_str = auth::role_to_string(new_role);
        spdlog::info("User role changed: {} {} -> {} by {}",
                    target_username, old_role_str, new_role_str, session->username);
        audit_fn_(req, "user.role_change", "success", "User", target_username,
                  "old_role=" + old_role_str + ",new_role=" + new_role_str);
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Role updated","level":"success"}})");
        res.set_content(render_users_fragment(session->username),
                        "text/html; charset=utf-8");
    });

    // -- Settings API: Enrollment tokens (admin only, HTMX) --------------------
    sink.Post("/api/settings/enrollment-tokens", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto label = extract_form_value(req.body, "label");
        auto max_uses_s = extract_form_value(req.body, "max_uses");
        auto ttl_s = extract_form_value(req.body, "ttl_hours");

        int max_uses = 0;
        int ttl_hours = 0;
        try {
            if (!max_uses_s.empty())
                max_uses = std::stoi(max_uses_s);
            if (!ttl_s.empty())
                ttl_hours = std::stoi(ttl_s);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(R"({"error":{"code":400,"message":"invalid numeric parameter"},"meta":{"api_version":"v1"}})", "application/json");
            return;
        }

        auto ttl =
            ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

        auto raw_token = auth_mgr_->create_enrollment_token(label, max_uses, ttl);

        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"Enrollment token created","level":"success"}})");
        res.set_content(render_tokens_fragment(raw_token), "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/enrollment-tokens/(.+))",
               [this](const httplib::Request& req, httplib::Response& res) {
                   if (!admin_fn_(req, res))
                       return;
                   auto token_id = req.matches[1].str();
                   auth_mgr_->revoke_enrollment_token(token_id);
                   res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Enrollment token revoked","level":"success"}})");
                   res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
               });

    // -- Batch enrollment token generation (JSON API for scripting) -------------
    sink.Post("/api/settings/enrollment-tokens/batch", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto label = extract_json_string(req.body, "label");
        auto count_s = extract_json_string(req.body, "count");
        auto max_uses_s = extract_json_string(req.body, "max_uses");
        auto ttl_s = extract_json_string(req.body, "ttl_hours");

        int count = 10;
        int max_uses = 1;
        int ttl_hours = 0;
        try {
            if (!count_s.empty())
                count = std::stoi(count_s);
            if (!max_uses_s.empty())
                max_uses = std::stoi(max_uses_s);
            if (!ttl_s.empty())
                ttl_hours = std::stoi(ttl_s);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(R"({"error":{"code":400,"message":"invalid numeric parameter"},"meta":{"api_version":"v1"}})", "application/json");
            return;
        }

        if (count < 1 || count > 10000) {
            res.status = 400;
            res.set_content(R"({"error":{"code":400,"message":"count must be 1-10000"},"meta":{"api_version":"v1"}})", "application/json");
            return;
        }

        auto ttl =
            ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

        auto tokens = auth_mgr_->create_enrollment_tokens_batch(label, count, max_uses, ttl);

        res.set_content(nlohmann::json({{"count", tokens.size()}, {"tokens", tokens}}).dump(),
                        "application/json");
    });

    // -- Settings API: API tokens (admin only, HTMX) ---------------------------
    sink.Post("/api/settings/api-tokens", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!perm_fn_(req, res, "ApiToken", "Write"))
            return;
        auto session = auth_fn_(req, res);
        if (!session)
            return;

        auto name = extract_form_value(req.body, "name");
        auto ttl_s = extract_form_value(req.body, "ttl_hours");
        auto mcp_tier = extract_form_value(req.body, "mcp_tier");

        if (name.empty()) {
            res.set_content(
                "<span class=\"feedback-error\">Token name is required.</span>",
                "text/html; charset=utf-8");
            return;
        }

        if (!mcp::is_valid_tier(mcp_tier)) {
            res.set_content(
                "<span class=\"feedback-error\">Invalid MCP tier. Must be readonly, operator, or supervised.</span>",
                "text/html; charset=utf-8");
            return;
        }

        int64_t expires_at = 0;
        if (!ttl_s.empty()) {
            try {
                int ttl_hours = std::stoi(ttl_s);
                if (ttl_hours > 0) {
                    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                    expires_at = now + static_cast<int64_t>(ttl_hours) * 3600;
                }
            } catch (const std::exception&) {
                res.set_content(
                    "<span class=\"feedback-error\">Invalid TTL value.</span>",
                    "text/html; charset=utf-8");
                return;
            }
        }

        auto result = api_token_store_->create_token(name, session->username, expires_at, {}, mcp_tier);
        if (!result) {
            res.set_content(
                "<span class=\"feedback-error\">" + html_escape(result.error()) + "</span>",
                "text/html; charset=utf-8");
            return;
        }

        spdlog::info("API token '{}' created by {}", name, session->username);

        if (audit_store_) {
            audit_store_->log({.principal = session->username,
                               .principal_role = auth::role_to_string(session->role),
                               .action = "api_token.create",
                               .target_type = "ApiToken",
                               .target_id = name,
                               .source_ip = req.remote_addr,
                               .result = "success"});
        }

        res.set_header("HX-Trigger",
            R"({"showToast":{"message":"API token created","level":"success"}})");
        std::string filter = session->role == auth::Role::admin ? std::string{}
                                                                : session->username;
        res.set_content(render_api_tokens_fragment(result.value(), filter),
                        "text/html; charset=utf-8");
    });

    sink.Delete(R"(/api/settings/api-tokens/(.+))",
               [this](const httplib::Request& req, httplib::Response& res) {
                   if (!perm_fn_(req, res, "ApiToken", "Delete"))
                       return;
                   auto session = auth_fn_(req, res);
                   if (!session)
                       return;
                   auto token_id = req.matches[1].str();

                   // Owner-scoped revocation (fixes the sibling IDOR to #222 on
                   // the HTMX dashboard path). A caller with ApiToken:Delete
                   // may only revoke their own tokens; the global admin role
                   // is the only bypass. We return a generic "not found"
                   // fragment in both the missing-id and the not-owner cases
                   // so the dashboard does not become an enumeration oracle.
                   auto existing = api_token_store_->get_token(token_id);
                   bool denied =
                       existing && existing->principal_id != session->username &&
                       session->role != auth::Role::admin;
                   if (!existing || denied) {
                       if (denied && audit_store_) {
                           audit_store_->log(
                               {.principal = session->username,
                                .principal_role = auth::role_to_string(session->role),
                                .action = "api_token.revoke",
                                .target_type = "ApiToken",
                                .target_id = token_id,
                                .detail = "owner=" + existing->principal_id,
                                .source_ip = req.remote_addr,
                                .result = "denied"});
                       }
                       // Return a minimal error-only fragment with zero token
                       // data. An earlier iteration of this fix rendered the
                       // full token table via render_api_tokens_fragment(),
                       // which leaked every user's token IDs to a denied
                       // probe — see governance Gate 4 unhappy-path UP-11.
                       // The pre-existing "success path renders all tokens"
                       // bug on `list_tokens()` with no owner filter is a
                       // separate follow-up (tracked: render_api_tokens_fragment
                       // must be scoped to the caller's principal or the
                       // panel must become admin-only).
                       res.status = 404;
                       res.set_header(
                           "HX-Trigger",
                           R"({"showToast":{"message":"Token not found","level":"error"}})");
                       res.set_content(
                           "<div class=\"error-fragment\" style=\"color:#f85149\">"
                           "Token not found.</div>",
                           "text/html; charset=utf-8");
                       return;
                   }

                   api_token_store_->revoke_token(token_id);

                   spdlog::info("API token '{}' revoked by {}", token_id, session->username);

                   if (audit_store_) {
                       audit_store_->log({.principal = session->username,
                                           .principal_role = auth::role_to_string(session->role),
                                           .action = "api_token.revoke",
                                           .target_type = "ApiToken",
                                           .target_id = token_id,
                                           .detail = "owner=" + existing->principal_id,
                                           .source_ip = req.remote_addr,
                                           .result = "success"});
                   }

                   res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"API token revoked","level":"success"}})");
                   std::string filter = session->role == auth::Role::admin
                                            ? std::string{}
                                            : session->username;
                   res.set_content(render_api_tokens_fragment({}, filter),
                                   "text/html; charset=utf-8");
               });

    // -- Settings API: Pending agents (admin only, HTMX) -----------------------

    // Bulk approve/deny — registered BEFORE the (.+) catch-all patterns
    sink.Post("/api/settings/pending-agents/bulk-approve",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 int count = 0;
                 for (const auto& a : auth_mgr_->list_pending_agents()) {
                     if (a.status == auth::PendingStatus::pending) {
                         auth_mgr_->approve_pending_agent(a.agent_id);
                         ++count;
                     }
                 }
                 spdlog::info("Bulk approved {} pending agent(s)", count);
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":")" + std::to_string(count) +
                     R"( agent(s) approved","level":"success"}})");
                 res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
             });

    sink.Post("/api/settings/pending-agents/bulk-deny",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 int count = 0;
                 for (const auto& a : auth_mgr_->list_pending_agents()) {
                     if (a.status == auth::PendingStatus::pending) {
                         auth_mgr_->deny_pending_agent(a.agent_id);
                         ++count;
                     }
                 }
                 spdlog::info("Bulk denied {} pending agent(s)", count);
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":")" + std::to_string(count) +
                     R"( agent(s) denied","level":"warning"}})");
                 res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
             });

    sink.Post(R"(/api/settings/pending-agents/(.+)/approve)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 auto agent_id = req.matches[1].str();
                 auth_mgr_->approve_pending_agent(agent_id);
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"Agent approved","level":"success"}})");
                 res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
             });

    sink.Post(R"(/api/settings/pending-agents/(.+)/deny)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 auto agent_id = req.matches[1].str();
                 auth_mgr_->deny_pending_agent(agent_id);
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"Agent denied","level":"warning"}})");
                 res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
             });

    sink.Delete(R"(/api/settings/pending-agents/(.+))",
               [this](const httplib::Request& req, httplib::Response& res) {
                   if (!admin_fn_(req, res))
                       return;
                   auto agent_id = req.matches[1].str();
                   auth_mgr_->remove_pending_agent(agent_id);
                   res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
               });

    // -- Settings API: Auto-approve rules (HTMX) ------------------------------

    sink.Post("/api/settings/auto-approve", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto type_s = extract_form_value(req.body, "type");
        auto value = extract_form_value(req.body, "value");
        auto label = extract_form_value(req.body, "label");

        auth::AutoApproveRuleType type;
        if (type_s == "trusted_ca")
            type = auth::AutoApproveRuleType::trusted_ca;
        else if (type_s == "ip_subnet")
            type = auth::AutoApproveRuleType::ip_subnet;
        else if (type_s == "cloud_provider")
            type = auth::AutoApproveRuleType::cloud_provider;
        else
            type = auth::AutoApproveRuleType::hostname_glob;

        auto_approve_->add_rule({type, value, label, true});
        spdlog::info("Auto-approve rule added: {}:{} ({})", type_s, value, label);
        res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
    });

    sink.Post("/api/settings/auto-approve/mode", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        auto mode = extract_form_value(req.body, "mode");
        auto_approve_->set_require_all(mode == "all");
        auto_approve_->save();
        spdlog::info("Auto-approve mode changed to {}", mode);
        res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
    });

    sink.Post(R"(/api/settings/auto-approve/(\d+)/toggle)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                 auto rules = auto_approve_->list_rules();
                 if (idx < rules.size()) {
                     auto_approve_->set_enabled(idx, !rules[idx].enabled);
                 }
                 res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
             });

    sink.Delete(R"(/api/settings/auto-approve/(\d+))",
               [this](const httplib::Request& req, httplib::Response& res) {
                   if (!admin_fn_(req, res))
                       return;
                   auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                   auto_approve_->remove_rule(idx);
                   spdlog::info("Auto-approve rule {} removed", idx);
                   res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
               });

    // -- Settings API: Management Groups (HTMX) --------------------------------

    sink.Post("/api/settings/management-groups",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ManagementGroup", "Write"))
                     return;
                 auto name = extract_form_value(req.body, "name");
                 auto parent_id = extract_form_value(req.body, "parent_id");
                 auto mtype = extract_form_value(req.body, "membership_type");
                 if (name.empty()) {
                     res.set_content(
                         "<span class=\"feedback-error\">Name required</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 ManagementGroup g;
                 g.name = name;
                 g.parent_id = parent_id;
                 g.membership_type = mtype.empty() ? "static" : mtype;
                 auto session = auth_fn_(req, res);
                 if (session)
                     g.created_by = session->username;
                 auto result = mgmt_group_store_->create_group(g);
                 if (!result) {
                     res.set_content(
                         "<span class=\"feedback-error\">" + result.error() + "</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 if (audit_store_) {
                     AuditEvent ae;
                     ae.principal = session ? session->username : "unknown";
                     ae.action = "management_group.create";
                     ae.target_type = "ManagementGroup";
                     ae.target_id = *result;
                     ae.detail = name;
                     ae.result = "success";
                     audit_store_->log(ae);
                 }
                 res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
             });

    sink.Delete(
        R"(/api/settings/management-groups/([a-f0-9]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "ManagementGroup", "Delete"))
                return;
            auto id = req.matches[1].str();
            auto result = mgmt_group_store_->delete_group(id);
            if (!result) {
                res.set_content(
                    "<span class=\"feedback-error\">" + result.error() + "</span>",
                    "text/html; charset=utf-8");
                return;
            }
            auto session = auth_fn_(req, res);
            if (audit_store_) {
                AuditEvent ae;
                ae.principal = session ? session->username : "unknown";
                ae.action = "management_group.delete";
                ae.target_type = "ManagementGroup";
                ae.target_id = id;
                ae.result = "success";
                audit_store_->log(ae);
            }
            res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
        });

    // -- Settings API: MCP toggle (HTMX POST) ---------------------------------
    sink.Post("/api/settings/mcp",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!admin_fn_(req, res))
                     return;
                 auto enabled_val = extract_form_value(req.body, "enabled");
                 auto read_only_val = extract_form_value(req.body, "read_only");
                 cfg_->mcp_disable = (enabled_val != "true");
                 cfg_->mcp_read_only = (read_only_val == "true");
                 spdlog::info("MCP settings changed: enabled={}, read_only={}",
                              !cfg_->mcp_disable, cfg_->mcp_read_only);
                 audit_fn_(req, "settings.mcp", "success", "MCP",
                           "mcp_settings",
                           "enabled=" + std::string(!cfg_->mcp_disable ? "true" : "false") +
                           ", read_only=" + std::string(cfg_->mcp_read_only ? "true" : "false"));
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"MCP settings saved","level":"success"}})");
                 res.set_content(render_mcp_fragment(), "text/html; charset=utf-8");
             });

    // -- Settings API: Update package management (admin only) -------------------

    sink.Post("/api/settings/updates/upload", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        if (!admin_fn_(req, res))
            return;
        if (!update_registry_) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">OTA disabled.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        std::string platform, arch, rollout_s, mandatory_s;
        if (req.has_param("platform"))
            platform = req.get_param_value("platform");
        if (req.has_param("arch"))
            arch = req.get_param_value("arch");
        if (req.has_param("rollout_pct"))
            rollout_s = req.get_param_value("rollout_pct");
        if (req.has_param("mandatory"))
            mandatory_s = req.get_param_value("mandatory");

        if (!SETTINGS_REQ_HAS_FILE(req, "file")) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">No file uploaded.</span>",
                            "text/html; charset=utf-8");
            return;
        }
        auto uploaded = SETTINGS_REQ_GET_FILE(req, "file");
        if (uploaded.content.empty()) {
            res.status = 400;
            res.set_content("<span class=\"feedback-error\">Empty file.</span>",
                            "text/html; charset=utf-8");
            return;
        }

        int rollout_pct = 100;
        try {
            if (!rollout_s.empty())
                rollout_pct = std::stoi(rollout_s);
        } catch (...) {}
        if (rollout_pct < 0)
            rollout_pct = 0;
        if (rollout_pct > 100)
            rollout_pct = 100;

        auto orig_name = uploaded.filename.empty() ? "yuzu-agent-" + platform + "-" + arch
                                                    : uploaded.filename;

        auto out_path =
            update_registry_->binary_path(UpdatePackage{platform, arch, "", "", orig_name});
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);
        {
            std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
            if (!f.is_open()) {
                res.status = 500;
                res.set_content("<span class=\"feedback-error\">Cannot write file.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            f.write(uploaded.content.data(),
                    static_cast<std::streamsize>(uploaded.content.size()));
        }

        auto sha = auth::AuthManager::sha256_hex(uploaded.content);
        auto version = orig_name;
        for (const auto* ext : {".exe", ".bin", ".tar.gz", ".zip", ".msi"}) {
            if (version.size() > std::strlen(ext) &&
                version.substr(version.size() - std::strlen(ext)) == ext) {
                version = version.substr(0, version.size() - std::strlen(ext));
                break;
            }
        }

        UpdatePackage pkg;
        pkg.platform = platform;
        pkg.arch = arch;
        pkg.version = version;
        pkg.sha256 = sha;
        pkg.filename = orig_name;
        pkg.mandatory = (mandatory_s == "true");
        pkg.rollout_pct = rollout_pct;
        pkg.file_size = static_cast<int64_t>(uploaded.content.size());

        update_registry_->upsert_package(pkg);
        spdlog::info("OTA package uploaded: {}/{} v{} ({}B, rollout={}%)", platform, arch,
                     version, pkg.file_size, rollout_pct);

        res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
    });

    sink.Delete(
        R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!admin_fn_(req, res))
                return;
            if (!update_registry_) {
                res.status = 400;
                return;
            }

            auto platform = req.matches[1].str();
            auto arch = req.matches[2].str();
            auto version = req.matches[3].str();

            auto packages = update_registry_->list_packages();
            for (const auto& pkg : packages) {
                if (pkg.platform == platform && pkg.arch == arch && pkg.version == version) {
                    auto bin_path = update_registry_->binary_path(pkg);
                    std::error_code ec;
                    std::filesystem::remove(bin_path, ec);
                    break;
                }
            }

            update_registry_->remove_package(platform, arch, version);
            spdlog::info("OTA package deleted: {}/{} v{}", platform, arch, version);
            res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
        });

    sink.Post(
        R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!admin_fn_(req, res))
                return;
            if (!update_registry_) {
                res.status = 400;
                return;
            }

            auto platform = req.matches[1].str();
            auto arch = req.matches[2].str();
            auto version = req.matches[3].str();
            auto pct_s = extract_form_value(req.body, "rollout_pct");

            int pct = 100;
            try {
                if (!pct_s.empty())
                    pct = std::stoi(pct_s);
            } catch (...) {}
            if (pct < 0)
                pct = 0;
            if (pct > 100)
                pct = 100;

            auto packages = update_registry_->list_packages();
            for (auto pkg : packages) {
                if (pkg.platform == platform && pkg.arch == arch && pkg.version == version) {
                    pkg.rollout_pct = pct;
                    update_registry_->upsert_package(pkg);
                    spdlog::info("OTA rollout updated: {}/{} v{} -> {}%", platform, arch,
                                 version, pct);
                    break;
                }
            }

            res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
        });
}

} // namespace yuzu::server
