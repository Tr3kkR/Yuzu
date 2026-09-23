#include "guardian_benchmark.hpp"
#include "baseline_store.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_retry.hpp"
#include "rest_a4_envelope_http.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <unordered_set>

extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {
namespace {
using Json = nlohmann::json;
constexpr std::size_t kCatalogBytes = 4 * 1024 * 1024;
bool text_field(const Json& j, const char* key, std::size_t limit, bool required = false) {
    if (!j.contains(key)) return !required;
    if (!j[key].is_string()) return false;
    const auto& s = j[key].get_ref<const std::string&>();
    return s.size() <= limit && s.find('\0') == std::string::npos && (!required || !s.empty());
}
bool revision_field(const Json& j, const char* key) {
    return j.contains(key) && j[key].is_number_integer() &&
           j[key] >= 0 && j[key] < std::numeric_limits<int64_t>::max();
}
bool safe_id(const std::string& s) {
    return !s.empty() && s.size() <= 128 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}
bool safe_url(const std::string& s) {
    return s.starts_with("https://") && s.size() > 8 && s.size() <= 2048 &&
           s.find_first_of("\r\n\t ") == std::string::npos;
}
BenchmarkError store_error(const std::string& error) {
    if (error.starts_with(kConflictPrefix)) return {409, "This record changed. Reload before saving."};
    return {503, "Benchmark decision store unavailable; retry after refreshing."};
}
Json decision_json(const BenchmarkDecision& d) {
    return {{"control_id", d.control_id}, {"value", d.value}, {"rationale", d.rationale},
            {"catalog_revision", d.catalog_revision},
            {"status", d.status}, {"revision", d.revision}, {"updated_by", d.updated_by},
            {"updated_at", d.updated_at}};
}
std::string str(const Json& j, const char* key) { return j.value(key, std::string{}); }
std::unordered_map<std::string, Json> decisions_by_id(const Json& document) {
    std::unordered_map<std::string, Json> result;
    for (auto d : document.at("decisions")) {
        if (d.value("catalog_revision", int64_t{0}) != document.at("catalog_revision").get<int64_t>()) {
            d["status"] = "proposed";
            d["rationale"] = "Catalog changed; review this previous decision. " + str(d, "rationale");
        }
        const auto id = str(d, "control_id");
        result.emplace(id, std::move(d));
    }
    return result;
}
Json resolved(const Json& c, const std::unordered_map<std::string, Json>& saved) {
    auto it = saved.find(str(c, "control_id"));
    if (it != saved.end()) return it->second;
    return {{"control_id", c["control_id"]}, {"value", str(c, "suggested_value")},
            {"rationale", str(c, "suggested_rationale")}, {"status", "proposed"},
            {"revision", 0}, {"updated_by", ""}, {"updated_at", 0}};
}
std::string sources_html(const Json& c) {
    std::string h;
    for (const auto& s : c.value("sources", Json::array())) {
        const auto url = str(s, "url");
        if (!safe_url(url)) continue;
        h += "<li>" + html_escape(str(s, "kind")) + ": <a href=\"" + html_escape(url) +
             "\" target=\"_blank\" rel=\"noopener noreferrer\">" + html_escape(str(s, "title")) + "</a></li>";
    }
    return h.empty() ? "<p>No external source linked for this control.</p>" : "<ul>" + h + "</ul>";
}
std::string export_table(const Json& document) {
    const auto saved = decisions_by_id(document);
    std::string h = "<table border=\"1\"><thead><tr><th>Control</th><th>Profile</th><th>Benchmark recommendation</th>"
        "<th>Suggested value</th><th>Organisation value</th><th>Decision status</th><th>Decision rationale</th>"
        "<th>Other choices and trade-offs</th><th>Sources</th><th>Last edited by</th></tr></thead><tbody>";
    for (const auto& c : document.at("catalog").at("controls")) {
        const auto d = resolved(c, saved);
        h += "<tr><td>" + html_escape(str(c, "control_id") + " — " + str(c, "title")) + "</td><td>" +
             (str(c, "profile") == "L2" ? "Level 2 additional hardening" : "Level 1") + "</td><td>" + html_escape(str(c, "benchmark_value")) +
             "</td><td>" + html_escape(str(c, "suggested_value")) + "</td><td>" + html_escape(str(d, "value")) +
             "</td><td>" + html_escape(str(d, "status")) + "</td><td>" + html_escape(str(d, "rationale")) + "</td><td>";
        for (const auto& a : c.value("alternatives", Json::array()))
            h += "<p><b>" + html_escape(str(a, "value")) + "</b>: " + html_escape(str(a, "reason")) +
                 " Trade-off: " + html_escape(str(a, "tradeoff")) + "</p>";
        h += "</td><td>" + html_escape(str(c, "benchmark_source")) + "<p>Research: " + html_escape(str(c, "research_status")) + "</p>" + sources_html(c) + "</td><td>" + html_escape(str(d, "updated_by")) + "</td></tr>";
    }
    return h + "</tbody></table>";
}

std::string render_helper(const Json& document) {
    const auto& catalog = document.at("catalog");
    const std::string bid = str(document, "baseline_id");
    const auto saved = decisions_by_id(document);
    const std::string api = "/api/v1/guaranteed-state/baselines/" + bid + "/benchmark";
    std::string h = "<style>.bm-card{border:1px solid var(--border);border-radius:6px;padding:1rem;margin:0.7rem 0}"
        ".bm-card summary{cursor:pointer;font-weight:600}.bm-card p{line-height:1.5}.bm-card label{display:block;margin-top:0.7rem}"
        ".bm-card textarea,.bm-card select{width:100%;background:var(--surface);color:var(--fg);border:1px solid var(--border);padding:0.6rem}"
        ".bm-source{font-size:0.8rem}.bm-card h3{margin-top:1rem}.bm-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}"
        "@media(max-width:700px){.bm-grid{grid-template-columns:1fr}}</style>";
    h += "<a class=\"gp-back\" href=\"/guardian/baseline/" + html_escape(bid) + "\">&larr; Baseline</a>"
         "<div class=\"gp-head\"><div><h1>Benchmark decisions</h1><p>" + html_escape(str(catalog, "name")) +
         " · " + html_escape(str(catalog, "version")) + "</p></div><a class=\"gp-btn\" target=\"_blank\" "
         "onclick=\"return benchmarkOpenSummary(event)\" href=\"/guardian/baseline/" + html_escape(bid) + "/decisions/export\">Copyable Confluence summary</a></div>"
         "<p>Review the suggested values, record your organisation's choice and explain why. Saving records a decision; "
         "it does not alter or deploy endpoint checks. Suggestions remain proposed until reviewed.</p>"
         "<p class=\"gp-note\">Review the sources supplied with this catalog. Community discussions are experience, "
         "not benchmark authority. Values outside the benchmark need an explicit exception. "
         "Save edits before opening the summary.</p>"
         "<div class=\"gp-filters\"><input id=\"bm-search\" placeholder=\"Search controls, registry paths or decisions\" "
         "oninput=\"benchmarkFilter()\"><select id=\"bm-profile\" onchange=\"benchmarkFilter()\">"
         "<option value=\"L1\" selected>Level 1</option><option value=\"all\">Level 1 + Level 2 hardening</option>"
         "</select><select id=\"bm-section\" onchange=\"benchmarkFilter()\"><option value=\"\">All policy sections</option>";
    std::unordered_set<std::string> sections;
    for (const auto& c : catalog.at("controls")) {
        const auto section = str(c, "section");
        if (!section.empty() && sections.insert(section).second)
            h += "<option value=\"" + html_escape(section) + "\">" + html_escape(section) + "</option>";
    }
    h += "</select><select id=\"bm-status\" onchange=\"benchmarkFilter()\"><option value=\"\">All decisions</option>"
         "<option value=\"proposed\">Needs review</option><option value=\"reviewed\">Reviewed</option>"
         "<option value=\"exception\">Exceptions</option><option value=\"not_applicable\">Not applicable</option></select></div>"
         "<p id=\"bm-count\">Review up to 10 controls at a time. Choose a policy section to focus your work.</p>"
         "<div class=\"gp-actions\"><button class=\"gp-btn\" id=\"bm-prev\" onclick=\"benchmarkBatch(-1)\">Previous batch</button>"
         "<button class=\"gp-btn\" id=\"bm-next\" onclick=\"benchmarkBatch(1)\">Next batch</button></div>";
    std::size_t initial_visible = 0;
    for (const auto& c : catalog.at("controls")) {
        const auto d = resolved(c, saved);
        const std::string id = str(c, "control_id");
        h += "<details class=\"bm-card\" data-section=\"" + html_escape(str(c, "section")) +
             "\" data-profile=\"" + html_escape(str(c, "profile")) +
             "\" data-status=\"" + html_escape(str(d, "status")) + "\" data-api=\"" + html_escape(api + "/decisions/" + id) +
             "\" data-revision=\"" + std::to_string(d.at("revision").get<int64_t>()) + "\" data-catalog=\"" +
             std::to_string(document.at("catalog_revision").get<int64_t>()) + "\"" +
             (str(c, "profile") != "L1" || initial_visible++ >= 10 ? " style=\"display:none\"" : "") + ">"
             "<summary>" + html_escape(id + " — " + str(c, "title")) + " <span class=\"gp-pill\">" +
             html_escape(str(c, "profile") == "L2" ? "Level 2 additional hardening" : "Level 1") +
             "</span> <span class=\"bm-decision-state gp-mute\">" + html_escape(str(d, "status")) +
             "</span></summary><p>" + html_escape(str(c, "description")) + "</p>"
             "<p><b>Risk mitigated:</b> " + html_escape(str(c, "rationale")) + "</p>"
             "<p><b>Registry / policy:</b> <code>" + html_escape(str(c, "location")) + "</code></p>"
             "<div class=\"bm-grid\"><div><h3>Benchmark recommendation</h3><p>" + html_escape(str(c, "benchmark_value")) +
             "</p><h3>Suggested starting value</h3><p>" + html_escape(str(c, "suggested_value")) + "</p><p>" +
             html_escape(str(c, "suggested_rationale")) + "</p></div><div><h3>Implementation impact</h3><p>" +
             html_escape(str(c, "impact")) + "</p><p><b>Guardian coverage:</b> " + html_escape(str(c, "coverage")) +
             "</p><p><b>Applicability:</b> " + html_escape(str(c, "applicability")) + "</p></div></div>"
             "<h3>Why an organisation might choose differently</h3>";
        const auto alternatives = c.value("alternatives", Json::array());
        if (alternatives.empty()) h += "<p>No researched alternative is recorded. Start with the benchmark recommendation and document any exception after compatibility testing.</p>";
        for (const auto& a : alternatives)
            h += "<p><b>" + html_escape(str(a, "value")) + "</b> — " + html_escape(str(a, "reason")) +
                 "<br><b>Trade-off:</b> " + html_escape(str(a, "tradeoff")) + "</p>";
        h += "<p class=\"gp-note\">Benchmark source: " + html_escape(str(c, "benchmark_source")) + "</p>"
             "<p class=\"gp-note\">Research: " + html_escape(str(c, "research_status")) + "</p>"
             "<div class=\"bm-source\">" + sources_html(c) + "</div>"
             "<label>Organisation value<textarea name=\"value\" rows=\"2\" maxlength=\"4096\" oninput=\"benchmarkDirty(this)\">" +
             html_escape(str(d, "value")) + "</textarea></label><label>Rationale for this decision<textarea name=\"rationale\" "
             "rows=\"3\" maxlength=\"16384\" oninput=\"benchmarkDirty(this)\">" + html_escape(str(d, "rationale")) +
             "</textarea></label><label>Decision status<select name=\"status\" onchange=\"benchmarkDirty(this)\">";
        for (const auto* status : {"proposed", "reviewed", "exception", "not_applicable"})
            h += "<option value=\"" + std::string(status) + "\"" + (str(d, "status") == status ? " selected" : "") + ">" + status + "</option>";
        h += "</select></label><p><button class=\"gp-btn accent\" onclick=\"benchmarkSave(this)\">Save decision</button> "
             "<span class=\"bm-save-status\" role=\"status\"></span></p></details>";
    }
    return h;
}
} // namespace

std::expected<Json, BenchmarkError> read_benchmark(BaselineStore& store, const std::string& id) {
    auto catalog = store.benchmark_catalog(id);
    if (!catalog) return std::unexpected(store_error(catalog.error()));
    if (!*catalog) return std::unexpected(BenchmarkError{404, "No benchmark decision catalog has been imported for this baseline."});
    auto data = Json::parse((**catalog).catalog_json, nullptr, false);
    if (data.is_discarded() || !data.is_object() || !data.contains("controls") || !data["controls"].is_array())
        return std::unexpected(BenchmarkError{503, "Stored benchmark catalog is invalid."});
    auto decisions = store.benchmark_decisions(id);
    if (!decisions) return std::unexpected(store_error(decisions.error()));
    Json ds = Json::array();
    for (const auto& d : *decisions) ds.push_back(decision_json(d));
    return Json{{"baseline_id", id}, {"catalog", std::move(data)}, {"catalog_revision", (**catalog).revision},
                {"catalog_updated_by", (**catalog).updated_by}, {"catalog_updated_at", (**catalog).updated_at},
                {"decisions", std::move(ds)}};
}

std::expected<Json, BenchmarkError> import_benchmark(BaselineStore& store, const std::string& id,
    const Json& body, const std::string& author) {
    auto invalid = [] { return std::unexpected(BenchmarkError{400, "Invalid benchmark catalog or revision."}); };
    if (!body.is_object() || !revision_field(body, "expected_revision") || !body.contains("catalog") ||
        !body["catalog"].is_object()) return invalid();
    const auto& c = body["catalog"];
    if (!text_field(c, "name", 512, true) || !text_field(c, "version", 128, true) ||
        !c.contains("controls") || !c["controls"].is_array() || c["controls"].empty() || c["controls"].size() > 1000 ||
        c.dump().size() > kCatalogBytes) return invalid();
    std::unordered_set<std::string> ids;
    for (const auto& row : c["controls"]) {
        if (!row.is_object() || !text_field(row, "control_id", 128, true) ||
            !safe_id(str(row, "control_id")) || !ids.insert(str(row, "control_id")).second ||
            !text_field(row, "title", 2048, true) || !text_field(row, "profile", 64, true)) return invalid();
        if (str(row, "profile") != "L1" && str(row, "profile") != "L2") return invalid();
        for (const auto* field : {"description", "rationale", "location", "benchmark_value", "suggested_value",
                                 "suggested_rationale", "impact", "coverage", "applicability", "research_status", "section", "benchmark_source"})
            if (!text_field(row, field, 16384)) return invalid();
        if (!text_field(row, "suggested_value", 4096)) return invalid();
        if (row.contains("value_kind") && (!text_field(row, "value_kind", 16) ||
            (str(row, "value_kind") != "text" && str(row, "value_kind") != "integer"))) return invalid();
        for (const auto* bound : {"minimum", "maximum"})
            if (row.contains(bound) && (!row[bound].is_number_integer() || row[bound] < 0 ||
                row[bound] >= std::numeric_limits<int64_t>::max())) return invalid();
        if (row.contains("minimum") && row.contains("maximum") && row["minimum"] > row["maximum"]) return invalid();
        if ((row.contains("minimum") || row.contains("maximum")) && str(row, "value_kind") != "integer") return invalid();
        if (row.contains("allowed_values")) {
            if (!row["allowed_values"].is_array() || row["allowed_values"].empty() || row["allowed_values"].size() > 32) return invalid();
            for (const auto& value : row["allowed_values"])
                if (!value.is_string() || value.get_ref<const std::string&>().size() > 4096 ||
                    value.get_ref<const std::string&>().find('\0') != std::string::npos) return invalid();
        }
        if (row.contains("alternatives")) {
            if (!row["alternatives"].is_array() || row["alternatives"].size() > 12) return invalid();
            for (const auto& a : row["alternatives"])
                if (!a.is_object() || !text_field(a, "value", 4096, true) ||
                    !text_field(a, "reason", 8192, true) || !text_field(a, "tradeoff", 8192, true)) return invalid();
        }
        if (row.contains("sources")) {
            if (!row["sources"].is_array() || row["sources"].size() > 24) return invalid();
            for (const auto& source : row["sources"])
                if (!source.is_object() || !text_field(source, "url", 2048, true) || !safe_url(str(source, "url")) ||
                    !text_field(source, "title", 1024, true) || !text_field(source, "kind", 128, true)) return invalid();
        }
    }
    bool store_ok = true;
    auto baseline = store.get_baseline(id, &store_ok);
    if (!store_ok) return std::unexpected(BenchmarkError{503, "Baseline store read failed."});
    if (!baseline) return std::unexpected(BenchmarkError{404, "Baseline not found."});
    auto saved = store.put_benchmark_catalog(id, c.dump(), author, body["expected_revision"].get<int64_t>());
    if (!saved) return std::unexpected(store_error(saved.error()));
    return read_benchmark(store, id);
}

std::expected<Json, BenchmarkError> update_benchmark_decision(BaselineStore& store,
    const std::string& id, const std::string& control_id, const Json& body, const std::string& author) {
    if (!body.is_object() || !revision_field(body, "expected_revision") || !revision_field(body, "catalog_revision") ||
        !text_field(body, "value", 4096) || !body.contains("value") ||
        !text_field(body, "rationale", 16384) || !body.contains("rationale") || !text_field(body, "status", 64, true))
        return std::unexpected(BenchmarkError{400, "Provide value, rationale, status and both revision numbers."});
    const std::string status = str(body, "status");
    if (status != "proposed" && status != "reviewed" && status != "exception" && status != "not_applicable")
        return std::unexpected(BenchmarkError{400, "Unknown decision status."});
    if (status != "proposed" && (str(body, "rationale").empty() || str(body, "value").empty()))
        return std::unexpected(BenchmarkError{400, "A reviewed decision needs an organisation value and rationale."});
    auto current = read_benchmark(store, id);
    if (!current) return std::unexpected(current.error());
    if ((*current)["catalog_revision"] != body["catalog_revision"])
        return std::unexpected(BenchmarkError{409, "The benchmark catalog changed. Reload before saving."});
    const auto& controls = (*current)["catalog"]["controls"];
    auto control = std::find_if(controls.begin(), controls.end(), [&](const auto& c) { return str(c, "control_id") == control_id; });
    if (control == controls.end())
        return std::unexpected(BenchmarkError{404, "Control not found in this benchmark catalog."});
    if (status == "reviewed") {
        const auto value = str(body, "value");
        bool conforms = true;
        if (str(*control, "value_kind") == "integer") {
            int64_t number = 0;
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
            conforms = parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
            if (conforms && control->contains("minimum")) conforms = number >= (*control)["minimum"].get<int64_t>();
            if (conforms && control->contains("maximum")) conforms = number <= (*control)["maximum"].get<int64_t>();
        }
        if (control->contains("allowed_values")) {
            const auto& allowed = (*control)["allowed_values"];
            conforms = conforms && std::find(allowed.begin(), allowed.end(), Json(value)) != allowed.end();
        }
        if (!conforms) return std::unexpected(BenchmarkError{400,
            "This value is outside the catalog's benchmark constraints. Choose Exception and explain the deviation."});
    }
    BenchmarkDecision decision;
    decision.control_id = control_id;
    decision.value = str(body, "value"); decision.rationale = str(body, "rationale"); decision.status = status;
    auto saved = store.save_benchmark_decision(id, decision, author, body["expected_revision"].get<int64_t>(),
                                              body["catalog_revision"].get<int64_t>());
    if (!saved) return std::unexpected(store_error(saved.error()));
    return decision_json(*saved);
}

std::string benchmark_export_html(const Json& document) {
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Benchmark decision record</title>"
        "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}td,th{padding:8px;vertical-align:top}"
        "th{background:#eee}button{padding:8px;margin-bottom:1rem}@media print{button{display:none}}</style></head><body>"
        "<button onclick=\"var r=document.createRange();r.selectNodeContents(document.getElementById('record'));"
        "var s=window.getSelection();s.removeAllRanges();s.addRange(r);var ok=document.execCommand('copy');"
        "this.textContent=ok?'Copied — paste into Confluence':'Selected — press Ctrl+C, then paste into Confluence'\">Copy table for Confluence</button>"
        "<article id=\"record\"><h1>" + html_escape(str(document.at("catalog"), "name")) + " — " +
        html_escape(str(document.at("catalog"), "version")) + "</h1><p>Decision record. Proposed values are unreviewed suggestions; "
        "this is not a compliance result or a deployment record.</p><p>Level 1 is the starting profile; Level 2 adds hardening that needs compatibility review. Research coverage varies by control; consult each row's research status. Community discussions are experience, not benchmark authority.</p>" + export_table(document) + "</article></body></html>";
}
std::string benchmark_export_markdown(const Json& document) {
    auto escape = [](std::string s) {
        std::string out;
        for (char c : html_escape(s)) { if (c == '|' || c == '\\') out += '\\'; out += (c == '\n' || c == '\r') ? ' ' : c; }
        return out;
    };
    const auto saved = decisions_by_id(document);
    std::string out = "# " + escape(str(document.at("catalog"), "name")) + " — " + escape(str(document.at("catalog"), "version")) +
        "\n\nProposed values are unreviewed suggestions. This is not a compliance or deployment record.\n\nLevel 1 is the starting profile; Level 2 adds hardening that needs compatibility review. Research coverage varies by control; consult each row's research status. Community discussions are experience, not benchmark authority.\n\n"
        "| Control | Profile | Benchmark recommendation | Suggested value | Organisation value | Status | Decision rationale | Alternatives and trade-offs | Sources |\n"
        "|---|---|---|---|---|---|---|---|---|\n";
    for (const auto& c : document.at("catalog").at("controls")) {
        const auto d = resolved(c, saved);
        std::string sources = str(c, "benchmark_source") + " Research: " + str(c, "research_status") + " ";
        std::string alternatives;
        for (const auto& a : c.value("alternatives", Json::array()))
            alternatives += str(a, "value") + ": " + str(a, "reason") + " Trade-off: " + str(a, "tradeoff") + " ";
        for (const auto& s : c.value("sources", Json::array())) sources += str(s, "title") + ": " + str(s, "url") + " ";
        out += "| " + escape(str(c, "control_id") + " " + str(c, "title")) + " | " + (str(c, "profile") == "L2" ? "Level 2 additional hardening" : "Level 1") +
            " | " + escape(str(c, "benchmark_value")) + " | " + escape(str(c, "suggested_value")) + " | " +
            escape(str(d, "value")) + " | " + escape(str(d, "status")) + " | " + escape(str(d, "rationale")) +
            " | " + escape(alternatives) + " | " + escape(sources) + " |\n";
    }
    return out;
}

void register_guardian_benchmark_routes(HttpRouteSink& sink, GuardianRoutes::AuthFn auth_fn,
    GuardianRoutes::PermFn perm, GuardianRoutes::AuditFn audit, BaselineStore* store) {
    auto fail = [](httplib::Response& res, int status, const std::string& message) {
        detail::A4ErrorOpts opts;
        if (status == 503 && message != "Baseline store unavailable." && message != "Audit sink unavailable.") {
            opts.retry_after_ms = mcp::kMcpStoreFaultRetryMs;
            opts.remediation = "Retry after the indicated delay; read current revisions before resubmitting a write.";
        } else if (status == 503) {
            opts.remediation = "Check the baseline store and audit configuration.";
        } else if (status == 409) {
            opts.remediation = "Read the current catalog and decisions, review changes, then resubmit.";
        }
        res.status = status;
        res.set_content(detail::a4_denial(res, status, message, opts), "application/json");
    };
    auto admit = [auth_fn, perm, fail](const httplib::Request& req, httplib::Response& res,
                                   const char* operation) -> std::optional<auth::Session> {
        res.set_header("Cache-Control", "no-store");
        auto session = auth_fn(req, res);
        if (!session) return std::nullopt;
        if (!session->token_scope_service.empty()) {
            fail(res, 403, "Service-scoped tokens cannot access fleet-wide benchmark decisions."); return std::nullopt;
        }
        if (!perm(req, res, "GuaranteedState", operation)) return std::nullopt;
        return session;
    };
    auto load = [store, fail](const std::string& id, httplib::Response& res) -> std::optional<Json> {
        if (!store) { fail(res, 503, "Baseline store unavailable."); return std::nullopt; }
        auto data = read_benchmark(*store, id);
        if (!data) { fail(res, data.error().status, data.error().message); return std::nullopt; }
        return *data;
    };
    auto audit_read = [audit, fail](const httplib::Request& req, httplib::Response& res, bool exporting) {
        try {
            if (!audit) { fail(res, 503, "Audit sink unavailable."); return false; }
            audit(req, exporting ? "guaranteed_state.benchmark.export" : "guaranteed_state.benchmark.read",
                  "success", "GuaranteedState", req.matches[1].str(), "benchmark decision metadata");
            return true;
        } catch (...) { fail(res, 503, "Audit recording failed."); return false; }
    };
    auto mutate = [store, admit, audit, fail](const httplib::Request& req, httplib::Response& res, bool catalog) {
        auto session = admit(req, res, "Write"); if (!session) return;
        if (!store) { fail(res, 503, "Baseline store unavailable."); return; }
        if (req.body.size() > kCatalogBytes || mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
            fail(res, 400, "Benchmark request exceeds its size or nesting limit."); return;
        }
        const auto body = Json::parse(req.body, nullptr, false);
        const auto id = req.matches[1].str();
        const std::string action = catalog ? "guaranteed_state.benchmark.import" : "guaranteed_state.benchmark.decision.update";
        try {
            if (!audit) { fail(res, 503, "Audit sink unavailable."); return; }
            audit(req, action, "attempt", "GuaranteedState", id, "benchmark decision metadata; no deployment");
        } catch (...) { fail(res, 503, "Audit recording failed; no decision was saved."); return; }
        auto result = catalog ? import_benchmark(*store, id, body, session->username)
                              : update_benchmark_decision(*store, id, req.matches[2].str(), body, session->username);
        if (!result) { fail(res, result.error().status, result.error().message); return; }
        // The attempted write was audited before persistence; a later audit error
        // must not falsely report that an already-committed choice was rolled back.
        try { audit(req, action, "success", "GuaranteedState", id, "benchmark decision metadata saved"); }
        catch (...) { spdlog::warn("{}: outcome audit failed after persistence", action); }
        res.set_content(Json{{"data", *result}}.dump(), "application/json");
    };
    sink.Get(R"(/api/v1/guaranteed-state/baselines/([A-Za-z0-9._\-]+)/benchmark)", [admit, load, audit_read](const auto& req, auto& res) {
        if (!admit(req, res, "Read")) return;
        auto d = load(req.matches[1].str(), res); if (!d) return;
        if (!audit_read(req, res, false)) return;
        res.set_content(Json{{"data", *d}}.dump(), "application/json");
    });
    sink.Put(R"(/api/v1/guaranteed-state/baselines/([A-Za-z0-9._\-]+)/benchmark)", [mutate](const auto& req, auto& res) { mutate(req, res, true); });
    sink.Put(R"(/api/v1/guaranteed-state/baselines/([A-Za-z0-9._\-]+)/benchmark/decisions/([A-Za-z0-9._\-]+))", [mutate](const auto& req, auto& res) { mutate(req, res, false); });
    sink.Get(R"(/api/v1/guaranteed-state/baselines/([A-Za-z0-9._\-]+)/benchmark/export)", [admit, load, fail, audit_read](const auto& req, auto& res) {
        if (!admit(req, res, "Read")) return;
        auto d = load(req.matches[1].str(), res); if (!d) return;
        const auto format = req.has_param("format") ? req.get_param_value("format") : "html";
        if (format != "html" && format != "markdown") { fail(res, 400, "format must be html or markdown"); return; }
        if (!audit_read(req, res, true)) return;
        res.set_content(Json{{"data", {{"format", format}, {"content", format == "html" ? benchmark_export_html(*d) : benchmark_export_markdown(*d)}}}}.dump(), "application/json");
    });
    sink.Get(R"(/guardian/baseline/([A-Za-z0-9._\-]+)/decisions)", [admit](const auto& req, auto& res) {
        if (!admit(req, res, "Read")) return;
        std::string page(kGuardianDetailPageHtml);
        for (const auto& [token, value] : std::vector<std::pair<std::string, std::string>>{
            {"{{TITLE}}", "Yuzu — Benchmark decisions"},
            {"{{FRAGMENT}}", "/fragments/guardian/baseline/" + req.matches[1].str() + "/decisions/page"}})
            for (auto pos = page.find(token); pos != std::string::npos; pos = page.find(token, pos + value.size())) page.replace(pos, token.size(), value);
        res.set_content(page, "text/html; charset=utf-8");
    });
    sink.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/decisions/page)", [admit, load, audit_read, store, fail](const auto& req, auto& res) {
        if (!admit(req, res, "Read")) return;
        const auto id = req.matches[1].str();
        auto d = load(id, res);
        if (d) {
            if (audit_read(req, res, false))
                res.set_content(render_helper(*d), "text/html; charset=utf-8");
            return;
        }
        if (res.status != 404 || !store) return;
        bool store_ok = true;
        const auto baseline = store->get_baseline(id, &store_ok);
        if (!store_ok) { fail(res, 503, "Baseline store read failed."); return; }
        if (!baseline || !audit_read(req, res, false)) return;
        res.status = 200;
        res.set_content("<h1>Benchmark decisions</h1><p>No benchmark catalog has been imported.</p>"
            "<p>Yuzu ships the decision workflow without third-party benchmark content. "
            "Import a catalog you are authorised to use through the benchmark REST API or "
            "the import_guardian_benchmark MCP tool.</p><p><a href=\"/guardian/baseline/" +
            html_escape(id) + "\">Return to baseline</a></p>", "text/html; charset=utf-8");
    });
    sink.Get(R"(/guardian/baseline/([A-Za-z0-9._\-]+)/decisions/export)", [admit, load, audit_read](const auto& req, auto& res) {
        if (!admit(req, res, "Read")) return;
        auto d = load(req.matches[1].str(), res); if (d && audit_read(req, res, true)) res.set_content(benchmark_export_html(*d), "text/html; charset=utf-8");
    });
}
} // namespace yuzu::server
