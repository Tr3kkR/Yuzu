/// @file test_tar_tree_routes.cpp
/// Route-level authz / token / audit tests for the TAR process-tree viewer
/// (/fragments/tar/process-tree{,/run,/result,/detail}). Driven in-process through
/// TestRouteSink (no httplib acceptor, #438) with stub auth/perm/dispatch/responses/
/// audit fns. These pin exactly the paths the pure-engine tests cannot reach — the
/// ones carrying the PR #1551 review findings:
///   * /detail holds the Execute tier (a Read-but-no-Execute operator is denied),
///   * a reconstruction token is bound to its originating principal (no cross-session
///     replay) and to the device scope (no cross-scope replay),
///   * the cache token is CSPRNG and an entropy failure fails closed (no cache entry),
///   * preset/os are neutralized in the audit detail.

#include "secure_random.hpp"
#include "tar_tree_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

DexAgentResponse resp(const std::string& agent_id, const std::string& output) {
    DexAgentResponse r;
    r.agent_id = agent_id;
    r.status = 1; // SUCCESS (terminal, carries output)
    r.output = output;
    return r;
}

// A canned $Process_Live body: systemd(1) -> bash(100). node 0 is systemd.
const char* kProcOut =
    "__schema__|ts|action|pid|ppid|name|cmdline|user\n"
    "100|started|1|0|systemd||root\n"
    "110|started|100|1|bash||alice\n";

// The two canned command ids the result route polls (must start with "tar-").
const std::string kProcCmd = "tar-p";
const std::string kTcpCmd = "tar-t";

// A TarTreeRoutes registered over a TestRouteSink with toggleable stubs.
struct TarHarness {
    yuzu::server::test::TestRouteSink sink;
    TarTreeRoutes routes;

    std::string device = "dev-A";
    std::string session_user = "alice";
    bool allow_read = true;
    bool allow_execute = true;
    std::string scope_device; // empty = unrestricted; else scoped Read denied elsewhere
    std::string os = "linux";
    std::string proc_output = kProcOut;
    std::string tcp_output;    // empty → tree renders without conns (best-effort TCP)
    bool audit_ok = true;      // #1647: flip to drop the evidence row (audit_fn → false)
    bool audit_throws = false; // #1647: simulate a bad_alloc-class throw out of audit_fn

    struct AuditRow {
        std::string action, result, target_id, detail;
    };
    std::vector<AuditRow> audit_log;

    TarHarness() {
        auto auth = [this](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            return s;
        };
        auto perm = [this](const httplib::Request&, httplib::Response&, const std::string&,
                           const std::string&) { return allow_read; };
        // Scoped gate: Execute toggled by allow_execute, Read by allow_read; a non-empty
        // scope_device denies any other device (mirrors a management-scope miss → 403).
        auto scoped = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string& op, const std::string& dev) {
            bool ok = (op == "Execute") ? allow_execute : allow_read;
            if (ok && !scope_device.empty() && dev != scope_device)
                ok = false;
            if (!ok)
                res.status = 403;
            return ok;
        };
        auto devices = [](const std::string&) { return std::vector<DeviceRow>{}; };
        auto lookup = [this](const std::string& id) -> std::optional<DeviceRow> {
            DeviceRow d;
            d.agent_id = id;
            d.os = os;
            return d;
        };
        // Dispatch returns a distinct tar- command id per query (process vs tcp),
        // keyed off the SQL the route built, so the responses stub can disambiguate.
        auto dispatch = [this](const std::string&, const std::string&, const std::vector<std::string>&,
                               const std::string&,
                               const std::unordered_map<std::string, std::string>& params)
            -> std::pair<std::string, int> {
            const auto it = params.find("sql");
            const bool is_proc =
                it != params.end() && it->second.find("$Process_Live") != std::string::npos;
            return {is_proc ? kProcCmd : kTcpCmd, 1};
        };
        auto responses = [this](const std::string& cmd,
                                 const std::string& /*agent_id*/) -> std::vector<DexAgentResponse> {
            if (cmd == kProcCmd)
                return {resp(device, proc_output)};
            if (cmd == kTcpCmd)
                return {resp(device, tcp_output)};
            return {};
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string&, const std::string& tid,
                            const std::string& d) -> bool {
            audit_log.push_back({a, r, tid, d});
            // #1647: the row is recorded before the throw so find_audit still proves the
            // site was reached; the throw then exercises the shared helper's catch-arm.
            if (audit_throws)
                throw std::runtime_error("audit DB write blew up");
            return audit_ok; // DexRoutes::AuditFn (aliased by TarTreeRoutes) is bool-returning (#1549)
        };
        routes.register_routes(sink, auth, perm, scoped, devices, lookup, dispatch, responses, audit);
    }

    // Drive /result directly (skips /run; the result route reads pcmd/tcmd from the
    // query, and we control the canned command ids). Returns the response.
    std::unique_ptr<httplib::Response> run_result(const std::string& extra = "") {
        return sink.Get("/fragments/tar/process-tree/result?device=" + device +
                        "&preset=10m&pcmd=" + kProcCmd + "&tcmd=" + kTcpCmd + "&n=1" + extra);
    }

    std::unique_ptr<httplib::Response> get_detail(const std::string& token, int node = 0) {
        return sink.Get("/fragments/tar/process-tree/detail?token=" + token +
                        "&node=" + std::to_string(node));
    }

    const AuditRow* find_audit(const std::string& action, const std::string& result) const {
        for (const auto& r : audit_log)
            if (r.action == action && r.result == result)
                return &r;
        return nullptr;
    }
};

// Pull the 32-hex reconstruction token out of a rendered tree fragment's detail URL.
std::string extract_token(const std::string& html) {
    const std::string needle = "detail?token=";
    auto p = html.find(needle);
    if (p == std::string::npos)
        return "";
    p += needle.size();
    auto end = html.find("&amp;", p);
    if (end == std::string::npos)
        end = html.size();
    return html.substr(p, end - p);
}

bool is_32_hex(const std::string& s) {
    if (s.size() != 32)
        return false;
    for (char c : s)
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    return true;
}

} // namespace

TEST_CASE("tar routes: reconstruction mints a 32-hex CSPRNG token", "[tar][routes][token]") {
    TarHarness h;
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200);
    const std::string token = extract_token(r->body);
    CHECK(is_32_hex(token));
    // The success audit fired with the data-class detail.
    REQUIRE(h.find_audit("tar.process_tree.read", "success") != nullptr);
}

TEST_CASE("tar routes: /detail renders for the owning operator + audits", "[tar][routes]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 200);
    CHECK(d->body.find("tar-detail") != std::string::npos);
    // Per-drilldown access audit fired with a neutralized os.
    const auto* row = h.find_audit("tar.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->target_id == "dev-A");
    CHECK(row->detail == "node=0 os=linux");
}

TEST_CASE("tar routes: /detail requires Execute (Read-only operator denied)",
          "[tar][routes][authz]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.allow_execute = false; // operator keeps scoped Read but loses Execute
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("Execute") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
    CHECK(h.find_audit("tar.process_tree.detail", "success") == nullptr);
}

TEST_CASE("tar routes: /detail rejects a token replayed by a different principal",
          "[tar][routes][authz]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body); // created by alice
    REQUIRE(is_32_hex(token));

    h.session_user = "mallory"; // same scope + Execute, but not the creator
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("different session") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
    CHECK(h.find_audit("tar.process_tree.detail", "success") == nullptr);
}

TEST_CASE("tar routes: /detail fails closed when the token's device leaves scope",
          "[tar][routes][authz]") {
    TarHarness h;
    h.scope_device = "dev-A"; // build under a device the operator manages
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.scope_device = "dev-B"; // dev-A now outside the operator's management scope
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 403);
    CHECK(d->body.find("tar-detail") == std::string::npos);
}

TEST_CASE("tar routes: CSPRNG failure fails closed (no cache, failure audit)",
          "[tar][routes][token]") {
    TarHarness h;
    test_hooks::force_next_failure_for_this_thread();
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200); // htmx-swappable in-panel note, NOT a 503
    CHECK(r->body.find("secure token") != std::string::npos);
    CHECK(!test_hooks::is_failure_forced_for_this_thread()); // override consumed
    // A failure audit row exists and NO token/tree was cached.
    REQUIRE(h.find_audit("tar.process_tree.read", "failure") != nullptr);
    CHECK(h.find_audit("tar.process_tree.read", "failure")->detail == "csprng_unavailable");
    CHECK(extract_token(r->body).empty());
    // A fabricated 32-hex token resolves to nothing (the cache is empty).
    auto d = h.get_detail("0123456789abcdef0123456789abcdef", 0);
    REQUIRE(d);
    CHECK(d->body.find("expired") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
}

TEST_CASE("tar routes: an over-cap process payload is rejected (no cache)",
          "[tar][routes][token]") {
    TarHarness h;
    h.proc_output = std::string(kMaxTarProcOutputBytes + 1, 'x'); // > 16 MiB
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("unexpectedly large") != std::string::npos);
    CHECK(extract_token(r->body).empty());                          // nothing rendered/cached
    CHECK(h.find_audit("tar.process_tree.read", "success") == nullptr);
}

TEST_CASE("tar routes: /detail audit normalizes the agent-controlled os",
          "[tar][routes][audit]") {
    TarHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    const auto* row = h.find_audit("tar.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail == "node=0 os=windows"); // normalized; no raw newline/'='
}

TEST_CASE("tar routes: /run audit neutralizes an injected preset", "[tar][routes][audit]") {
    TarHarness h;
    // preset carries an audit-field-forgery attempt; canonicalization maps it to 10m.
    auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=x%20command_id%3Dforged");
    REQUIRE(r);
    const auto* row = h.find_audit("tar.process_tree.read", "dispatched");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("preset=10m") != std::string::npos);
    CHECK(row->detail.find("forged") == std::string::npos); // injection neutralized
}

TEST_CASE("tar routes: /result audit normalizes an agent-controlled os", "[tar][routes][audit]") {
    TarHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    h.run_result();
    const auto* row = h.find_audit("tar.process_tree.read", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("os=windows") != std::string::npos);
    CHECK(row->detail.find("evil=1") == std::string::npos);
    CHECK(row->detail.find('\n') == std::string::npos); // no line splitting
}

TEST_CASE("tar routes: /run is denied for a Read-but-no-Execute operator",
          "[tar][routes][authz]") {
    TarHarness h;
    h.allow_execute = false;
    auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m");
    REQUIRE(r);
    CHECK(r->body.find("Execute") != std::string::npos);
    // No dispatch audit when the Execute gate stops the reconstruction.
    CHECK(h.find_audit("tar.process_tree.read", "dispatched") == nullptr);
}

// #1647 catch-arm parity: a THROWING audit_fn at every tar dispatch/read site must be
// caught by the shared rest_audit.hpp chokepoint — never escape the handler (which
// httplib would turn into a 500) — and must surface Sec-Audit-Failed while the route
// keeps its existing dispatch/render posture. Before #1647 these sites discarded the
// audit bool with no try/catch, so a bad_alloc-class throw escaped and a dropped row
// was invisible. One section per distinct call site.
TEST_CASE("tar routes: a throwing audit_fn is caught + flags Sec-Audit-Failed at every site",
          "[tar][routes][audit]") {
    SECTION("/run — tar.process_tree.read dispatched") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Posture preserved: the dispatch still rendered the polling fragment.
        CHECK(r->body.find("process-tree/result") != std::string::npos);
        CHECK(h.find_audit("tar.process_tree.read", "dispatched") != nullptr);
    }
    SECTION("/result success — tar.process_tree.read success (renders PII tree)") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Set-and-proceed: the tree still rendered (a detail token was minted).
        CHECK(is_32_hex(extract_token(r->body)));
    }
    SECTION("/result csprng failure — tar.process_tree.read failure") {
        TarHarness h;
        h.audit_throws = true;
        test_hooks::force_next_failure_for_this_thread(); // forces the failure-audit branch
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("secure token") != std::string::npos); // honest note still rendered
        CHECK(h.find_audit("tar.process_tree.read", "failure") != nullptr);
    }
    SECTION("/detail — tar.process_tree.detail") {
        TarHarness h;
        const std::string token = extract_token(h.run_result()->body); // clean reconstruction
        REQUIRE(is_32_hex(token));
        h.audit_throws = true; // throw only on the detail open
        std::unique_ptr<httplib::Response> d;
        CHECK_NOTHROW(d = h.get_detail(token, 0));
        REQUIRE(d);
        CHECK(d->status == 200);
        CHECK(d->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(d->body.find("tar-detail") != std::string::npos); // detail still rendered
    }
    SECTION("/device-net — tar.dns.read + tar.arp.read") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Both verbs were reached before the throw was caught.
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/load — tar.sources.read") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/capture-sources/load?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("tar.sources.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push — tar.sources.configure") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        // changes=process=on (url-encoded '='); a known source toggled on.
        CHECK_NOTHROW(
            r = h.sink.Post("/fragments/tar/capture-sources/push?device=dev-A&changes=process%3Don",
                            ""));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("tar.sources.configure", "dispatched") != nullptr);
    }
}

// #1647: a DROPPED (returns-false) audit row is the realistic failure path (audit DB
// locked/full). Before this PR the tar sites discarded the bool and set NO header; now
// they surface Sec-Audit-Failed while still rendering (set-and-proceed). Also pins the
// idempotent-header guard: the two MULTI-CALL surfaces (dns+arp, the configure loop)
// must emit Sec-Audit-Failed AT MOST ONCE even when several audits in one request fail.
TEST_CASE("tar routes: dropped audit row flags Sec-Audit-Failed once; clean path sets none",
          "[tar][routes][audit]") {
    SECTION("/run dropped row — set-and-proceed (header + still dispatches)") {
        TarHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("process-tree/result") != std::string::npos); // dispatch not blocked
    }
    SECTION("/device-net both dns+arp drop — header emitted exactly once (multimap guard)") {
        TarHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1); // not two field-lines
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/device-net both dns+arp throw — header still exactly once") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH verbs must have fired (the first throw was caught, the second still ran)
        // — otherwise count==1 would prove single-emission, not de-duplication.
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push two sources both drop — header exactly once over the loop") {
        TarHarness h;
        h.audit_ok = false;
        // Two known sources toggled in one request; the per-source audit loop fails twice.
        auto r = h.sink.Post(
            "/fragments/tar/capture-sources/push?device=dev-A&changes=process%3Don,tcp%3Doff", "");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH loop iterations must have reached the audit chokepoint — otherwise
        // count==1 could mean the loop skipped the second source, not de-duplication.
        int cfg_rows = 0;
        for (const auto& row : h.audit_log)
            if (row.action == "tar.sources.configure")
                ++cfg_rows;
        CHECK(cfg_rows == 2);
    }
    SECTION("clean path sets NO Sec-Audit-Failed header") {
        TarHarness h; // audit_ok=true, audit_throws=false
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
        CHECK(is_32_hex(extract_token(r->body))); // tree rendered normally
    }
}
