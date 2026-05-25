/**
 * test_agent_service_impl.cpp — coverage for AgentServiceImpl response-path
 * helpers. Closes the gap explicitly deferred at
 * test_workflow_routes.cpp:820 ("no AgentServiceImpl in ExecHarness")
 * by constructing a real AgentServiceImpl and driving response receipt
 * end-to-end into a real ResponseStore.
 *
 * Pins three contracts called out in #117 (response-streaming coverage):
 *
 *   1. record_execution_id() registers the command_id → execution_id
 *      mapping consumed at response receipt; passing an empty
 *      execution_id removes the entry (the documented "clear" semantics
 *      from agent_service_impl.cpp:586).
 *
 *   2. process_gateway_response() stamps execution_id onto every
 *      StoredResponse (RUNNING and terminal branches both), so the
 *      executions detail drawer's `query_by_execution` path sees the
 *      stream. A response with no recorded mapping degrades cleanly —
 *      execution_id stays empty rather than crashing or fabricating.
 *
 *   3. The HF-1 multi-agent fan-out invariant: the terminal branch
 *      MUST NOT erase the mapping after the first agent's terminal
 *      response, otherwise agents 2..N stamp empty execution_id and
 *      the drawer drops them. This was a real PR-2 hardening regression
 *      (see agent_service_impl.cpp:672-674); the response-store-level
 *      pin at test_workflow_routes.cpp:814 only proves the store
 *      handles two stamped rows — this test proves the upstream path
 *      actually emits two stamped rows from a single mapping.
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "event_bus.hpp"
#include "execution_tracker.hpp"
#include "gateway_service_impl.hpp"
#include "peer_ip.hpp"
#include "response_store.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include <memory>
#include <random>
#include <string>

using yuzu::server::AuditStore;
using yuzu::server::ResponseStore;
using yuzu::server::StoredResponse;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;

namespace {

namespace apb = ::yuzu::agent::v1;

/// Minimal harness: real AgentServiceImpl wired against in-memory
/// ResponseStore. analytics/notification/webhook stores stay null so
/// the side-effect branches in process_gateway_response short-circuit
/// on their `if (store_)` guards — keeps the test focused on the
/// execution_id stamping invariant.
///
/// MEMBER ORDER LOAD-BEARING: members below are declared in topological
/// order so that every reference captured by `svc` (and by `registry`)
/// points at an already-constructed member, AND so that `responses`
/// destructs AFTER `svc` (it is declared earlier than `svc`, so it
/// destructs later than `svc`). `svc` holds `response_store_` as a raw
/// `ResponseStore*` (set in the body); reordering would create a
/// dangling-pointer hazard at `~svc`. Do not alphabetise.
struct GatewayResponseHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    ResponseStore responses{":memory:"};
    AuditStore audit{":memory:"};
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    GatewayResponseHarness() {
        REQUIRE(responses.is_open());
        REQUIRE(audit.is_open());
        svc.set_response_store(&responses);
        svc.set_audit_store(&audit);
    }

    static apb::CommandResponse make_response(const std::string& command_id,
                                              apb::CommandResponse::Status status,
                                              const std::string& output = "", int exit_code = 0) {
        apb::CommandResponse r;
        r.set_command_id(command_id);
        r.set_status(status);
        r.set_output(output);
        r.set_exit_code(exit_code);
        return r;
    }
};

} // namespace

// ── record_execution_id ────────────────────────────────────────────────────

TEST_CASE("record_execution_id: terminal response stamps mapped execution_id",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-A", "exec-42");

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    auto rows = h.responses.query_by_execution("exec-42");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].execution_id == "exec-42");
    CHECK(rows[0].agent_id == "agent-1");
    CHECK(rows[0].instruction_id == "cmd-A");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}

TEST_CASE("record_execution_id: empty execution_id removes the mapping",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-A", "exec-42");
    h.svc.record_execution_id("cmd-A", ""); // documented clear semantics

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_exec = h.responses.query_by_execution("exec-42");
    CHECK(by_exec.empty()); // mapping cleared → row not tagged
    auto by_cmd = h.responses.get_by_instruction("cmd-A");
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── process_gateway_response: per-status branches ──────────────────────────

TEST_CASE("process_gateway_response: RUNNING streaming row carries execution_id",
          "[agent_service][executions][pr2]") {
    // The RUNNING branch lives at agent_service_impl.cpp:597-655 — it both
    // stores a streaming row and stamps execution_id from the same map.
    // Pin both halves: the row exists AND it carries the tag.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-stream", "exec-stream");

    auto running =
        GatewayResponseHarness::make_response("cmd-stream", apb::CommandResponse::RUNNING,
                                              /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", running);

    auto rows = h.responses.query_by_execution("exec-stream");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));
    CHECK(rows[0].output == "row-1");
}

TEST_CASE("process_gateway_response: FAILURE preserves error_detail and execution_id",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-fail", "exec-fail");

    auto resp = GatewayResponseHarness::make_response("cmd-fail", apb::CommandResponse::FAILURE,
                                                      /*output=*/"",
                                                      /*exit_code=*/2);
    resp.mutable_error()->set_message("plugin returned non-zero");
    h.svc.process_gateway_response("agent-1", resp);

    auto rows = h.responses.query_by_execution("exec-fail");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].error_detail == "plugin returned non-zero");
    CHECK(rows[0].execution_id == "exec-fail");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
}

TEST_CASE("process_gateway_response: unmapped command_id stamps empty execution_id",
          "[agent_service][executions][pr2]") {
    // Out-of-band dispatch (CLI / direct gRPC) bypasses the dispatch path
    // that calls record_execution_id. The receipt path must degrade to an
    // empty execution_id rather than crashing or inventing a value.
    GatewayResponseHarness h;
    auto resp = GatewayResponseHarness::make_response("cmd-orphan", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_cmd = h.responses.get_by_instruction("cmd-orphan");
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── HF-1 multi-agent fan-out invariant ─────────────────────────────────────

TEST_CASE("process_gateway_response: terminal branch does NOT erase mapping "
          "(HF-1 multi-agent fan-out invariant)",
          "[agent_service][executions][pr2][hardening]") {
    // PR-2 ladder regression. Pre-fix, the terminal branch erased
    // cmd_execution_ids_ on the FIRST agent's response so agents 2..N
    // stamped empty execution_id and the executions drawer dropped them.
    // The fix at agent_service_impl.cpp:672-674 keeps the mapping live
    // until a future sweeper. This test drives the path the test_workflow_
    // routes pin couldn't reach (it operated on ResponseStore directly).
    //
    // Fan out across 4 agents and mix terminal statuses (SUCCESS / FAILURE /
    // TIMEOUT) to pin two distinct invariants simultaneously: (a) the
    // mapping survives every terminal-status code path (`else` branch at
    // agent_service_impl.cpp:656 covers all non-RUNNING statuses uniformly,
    // a future split that re-introduces an erase on FAILURE-only or
    // TIMEOUT-only would slip past a SUCCESS-only test); and (b) tail
    // agents (#4) past the smallest fan-out width still stamp correctly,
    // closing the off-by-one window where a regression could erase after
    // exactly N=3 calls.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-fan", "exec-fan");

    struct AgentTerminal {
        const char* agent;
        apb::CommandResponse::Status status;
    };
    const AgentTerminal terminals[] = {
        {"agent-1", apb::CommandResponse::SUCCESS},
        {"agent-2", apb::CommandResponse::FAILURE},
        {"agent-3", apb::CommandResponse::TIMEOUT},
        {"agent-4", apb::CommandResponse::SUCCESS},
    };
    for (const auto& t : terminals) {
        auto r = GatewayResponseHarness::make_response("cmd-fan", t.status);
        h.svc.process_gateway_response(t.agent, r);
    }

    auto rows = h.responses.query_by_execution("exec-fan");
    REQUIRE(rows.size() == 4);
    for (const auto& row : rows) {
        CHECK(row.execution_id == "exec-fan");
        CHECK(row.error_detail.empty()); // SUCCESS path must not invent error_detail
    }
}

TEST_CASE("process_gateway_response: __timing__ sentinel takes the early-return "
          "branch and does NOT store",
          "[agent_service][executions][pr2]") {
    // The RUNNING branch at agent_service_impl.cpp:599-606 short-circuits
    // for output starting with "__timing__|" — these are out-of-band
    // dashboard-stat payloads, not command output. They must NOT appear
    // in ResponseStore (no execution_id stamp, no instruction row).
    // Without this pin, a refactor that hoists the store block above the
    // sentinel guard would silently start persisting timing rows under the
    // execution_id, which the drawer would then surface as bogus output.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-time", "exec-time");

    auto timing = GatewayResponseHarness::make_response("cmd-time", apb::CommandResponse::RUNNING,
                                                        /*output=*/"__timing__|elapsed=42");
    h.svc.process_gateway_response("agent-1", timing);

    CHECK(h.responses.query_by_execution("exec-time").empty());
    CHECK(h.responses.get_by_instruction("cmd-time").empty());
}

TEST_CASE("process_gateway_response: terminal SUCCESS folds into existing RUNNING rows",
          "[agent_service][executions][pr2]") {
    // Post-UAT 2026-05-06: an empty-output terminal frame is folded into
    // the existing RUNNING rows in place via
    // ResponseStore::finalize_terminal_status, instead of inserting a
    // separate sentinel row that operators misread as a failed run that
    // happened "before" the data row. Two streaming RUNNING rows + a
    // terminal SUCCESS = 2 rows, both updated to SUCCESS, both still
    // tagged with the same execution_id.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-mix", "exec-mix");

    auto r1 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-1");
    h.svc.process_gateway_response("agent-1", r1);
    auto r2 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-2");
    h.svc.process_gateway_response("agent-1", r2);
    auto r3 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", r3);

    auto rows = h.responses.query_by_execution("exec-mix");
    REQUIRE(rows.size() == 2);
    for (const auto& row : rows) {
        CHECK(row.status == static_cast<int>(apb::CommandResponse::SUCCESS));
        CHECK(row.execution_id == "exec-mix");
    }
}

TEST_CASE("process_gateway_response: terminal frame WITH output still inserts",
          "[agent_service][executions][pr2]") {
    // Edge case: a plugin whose terminal frame carries the result data
    // (rather than streaming via RUNNING + sentinel terminal) should
    // still produce a row, since finalize_terminal_status only fires
    // when the terminal output is empty.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-direct", "exec-direct");
    auto only = GatewayResponseHarness::make_response("cmd-direct", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"final-data");
    h.svc.process_gateway_response("agent-1", only);

    auto rows = h.responses.query_by_execution("exec-direct");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
    CHECK(rows[0].output == "final-data");
}

TEST_CASE("process_gateway_response: re-mapping a command_id updates the stamp",
          "[agent_service][executions][pr2]") {
    // Defensive contract: if the dispatch path overwrites a command_id's
    // mapping (e.g. retry under a new execution row), responses arriving
    // after the overwrite stamp the new execution_id. Old execution_id
    // sees only pre-overwrite responses.
    //
    // Post-UAT 2026-05-06: the terminal-frame finalize path is scoped by
    // execution_id, so a terminal SUCCESS arriving after the re-mapping
    // does NOT fold back onto the old execution's row. With no RUNNING
    // row under exec-new, finalize matches zero rows and falls through
    // to insert (preserving the re-mapping invariant).
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-re", "exec-old");
    auto first = GatewayResponseHarness::make_response("cmd-re", apb::CommandResponse::RUNNING,
                                                       /*output=*/"old");
    h.svc.process_gateway_response("agent-1", first);

    h.svc.record_execution_id("cmd-re", "exec-new");
    auto second = GatewayResponseHarness::make_response("cmd-re", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", second);

    auto old_rows = h.responses.query_by_execution("exec-old");
    REQUIRE(old_rows.size() == 1);
    CHECK(old_rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));

    auto new_rows = h.responses.query_by_execution("exec-new");
    REQUIRE(new_rows.size() == 1);
    CHECK(new_rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}

// ── #826 — Subscribe peer-mismatch IP extraction ───────────────────────────

TEST_CASE("AgentServiceImpl::extract_peer_ip handles ipv4/ipv6/unix peer encodings",
          "[agent_service][peer_mismatch][issue826]") {
    // gRPC peer encoding is documented at
    // src/core/lib/iomgr/parse_address.cc; the parser must round-trip
    // every shape it produces so the Subscribe peer-mismatch check can
    // operate on IPs (ports differ per-RPC, IPs do not).
    using yuzu::server::detail::AgentServiceImpl;

    CHECK(AgentServiceImpl::extract_peer_ip("ipv4:1.2.3.4:5678") == "1.2.3.4");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv4:127.0.0.1:50051") == "127.0.0.1");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[::1]:50051") == "::1");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[2001:db8::1]:443") == "2001:db8::1");
    // unix-domain sockets have no IP to extract → empty. Caller MUST
    // treat empty as a mismatch (never as a wild match) to avoid #826.
    CHECK(AgentServiceImpl::extract_peer_ip("unix:/tmp/sock").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("").empty());
    // Malformed/unknown scheme → empty
    CHECK(AgentServiceImpl::extract_peer_ip("garbage").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:no-brackets:8080").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[unclosed").empty());
}

TEST_CASE("extract_peer_ip strict-mode rejects malformed addresses (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // ipv4 bodies that are not a valid dotted-quad → empty. The previous lax
    // parser returned a half-parsed substring that could slip past the #826
    // binding comparison.
    CHECK(extract_peer_ip("ipv4:not.an.ip:80").empty());
    CHECK(extract_peer_ip("ipv4:1.2.3:80").empty());     // 3 octets
    CHECK(extract_peer_ip("ipv4:1.2.3.4.5:80").empty()); // 5 octets
    CHECK(extract_peer_ip("ipv4:999.1.1.1:80").empty()); // octet > 255
    CHECK(extract_peer_ip("ipv4:1.2.3.4.:80").empty());  // trailing dot
    CHECK(extract_peer_ip("ipv4::80").empty());          // empty address
    CHECK(extract_peer_ip("ipv4:01.02.03.04:80").empty()); // leading-zero octets (non-canonical)
    CHECK(extract_peer_ip("ipv4:1.2.3.04:80").empty());    // single leading-zero octet
    CHECK(extract_peer_ip("ipv4:0.0.0.0:80") == "0.0.0.0"); // bare-zero octets are canonical
    // ipv6 bodies with non-hex junk in the address → empty
    CHECK(extract_peer_ip("ipv6:[xyz]:80").empty());
    CHECK(extract_peer_ip("ipv6:[g::1]:80").empty()); // 'g' not hex
    CHECK(extract_peer_ip("ipv6:[]:80").empty());     // empty address
    CHECK(extract_peer_ip("ipv6:[1234]:80").empty()); // no colon → not v6
    // valid shapes still pass, including a v6 zone id (interface name is
    // non-hex but legitimate after '%').
    CHECK(extract_peer_ip("ipv4:10.0.0.1:443") == "10.0.0.1");
    CHECK(extract_peer_ip("ipv6:[fe80::1%eth0]:443") == "fe80::1%eth0");
}

TEST_CASE("extract_peer_ip canonicalizes IPv6 to lowercase (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // Register-side vs subscribe-side comparison must not depend on hex
    // casing — both sides route through this function so lowercasing is
    // symmetric. (gRPC emits canonical lowercase today; this defends the
    // comparison if that ever changes.)
    CHECK(extract_peer_ip("ipv6:[2001:DB8::1]:443") == "2001:db8::1");
    CHECK(extract_peer_ip("ipv6:[FE80::AbCd]:443") == "fe80::abcd");
    // IPv4-mapped IPv6 (dual-stack listener accepting an IPv4 client) — '.' is
    // allowed in the v6 body; uppercase folds to lower.
    CHECK(extract_peer_ip("ipv6:[::ffff:1.2.3.4]:80") == "::ffff:1.2.3.4");
    CHECK(extract_peer_ip("ipv6:[::FFFF:1.2.3.4]:80") == "::ffff:1.2.3.4");
    CHECK(extract_peer_ip("ipv4:1.2.3.4:5") == "1.2.3.4"); // ipv4 needs no folding
}

TEST_CASE("extract_peer_ip register/subscribe comparison is casing-symmetric (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // The #826 binding check compares extract_peer_ip(register) vs
    // extract_peer_ip(subscribe). The same IP in different hex casing / port
    // MUST compare equal after canonicalization, or a legit agent reconnecting
    // via a differently-cased peer string would be locked out.
    CHECK(extract_peer_ip("ipv6:[FE80::1]:443") == extract_peer_ip("ipv6:[fe80::1]:9999"));
    CHECK(extract_peer_ip("ipv6:[2001:DB8::AB]:1") == extract_peer_ip("ipv6:[2001:db8::ab]:2"));
    CHECK(extract_peer_ip("ipv4:1.2.3.4:443") == extract_peer_ip("ipv4:1.2.3.4:55"));
}

TEST_CASE("extract_peer_ip never returns junk on arbitrary input (#1058)",
          "[agent_service][peer_mismatch][issue1058][fuzz]") {
    using yuzu::server::detail::extract_peer_ip;
    using yuzu::server::detail::is_plausible_ipv6;
    using yuzu::server::detail::is_valid_ipv4;
    // Deterministic fuzz: random bytes from a hostile alphabet (colons,
    // brackets, percent, whitespace, non-hex letters) must never throw, and any
    // non-empty result must itself validate as one of the two accepted shapes —
    // the strict-mode guarantee under adversarial input.
    std::mt19937 rng(0xC0FFEE);
    const std::string alphabet = "ipv46:[]%.-_0123456789abcdefABCDEFxyz/ \t";
    std::uniform_int_distribution<std::size_t> len_dist(0, 40);
    std::uniform_int_distribution<std::size_t> ch_dist(0, alphabet.size() - 1);
    for (int iter = 0; iter < 20000; ++iter) {
        std::string s;
        const std::size_t n = len_dist(rng);
        for (std::size_t i = 0; i < n; ++i)
            s.push_back(alphabet[ch_dist(rng)]);
        const auto out = extract_peer_ip(s);
        if (!out.empty()) {
            CHECK((is_valid_ipv4(out) || is_plausible_ipv6(out)));
        }
    }
}

// ── #1064 — normalize_bare_ip (gateway_observed_peer parsing) ───────────────

TEST_CASE("normalize_bare_ip accepts canonical bare IPs, rejects junk (#1064)",
          "[agent_service][peer_mismatch][issue1064]") {
    using yuzu::server::detail::normalize_bare_ip;
    // The gateway fills RegisterRequest.gateway_observed_peer with a BARE IP
    // (no gRPC scheme/port). Valid IPv4 passes through; IPv6 is lowercased so it
    // compares equal to an extract_peer_ip() value from the same address.
    CHECK(normalize_bare_ip("203.0.113.7") == "203.0.113.7");
    CHECK(normalize_bare_ip("10.0.0.1") == "10.0.0.1");
    CHECK(normalize_bare_ip("2001:DB8::1") == "2001:db8::1");
    CHECK(normalize_bare_ip("fe80::1%eth0") == "fe80::1%eth0");

    // Anything not a clean literal → empty, so the caller falls back to the
    // transport (gateway) IP rather than recording attacker-controlled junk.
    CHECK(normalize_bare_ip("").empty());
    CHECK(normalize_bare_ip("not-an-ip").empty());
    CHECK(normalize_bare_ip("999.1.1.1").empty());        // octet > 255
    CHECK(normalize_bare_ip("01.02.03.04").empty());      // leading-zero (non-canonical)
    CHECK(normalize_bare_ip("ipv4:1.2.3.4:80").empty());  // gRPC framing is NOT a bare IP
    CHECK(normalize_bare_ip("1.2.3.4 ; rm -rf").empty()); // no injection round-trips
}

// ── #1128 — NAT-aware peer-binding decision (evaluate_peer_binding) ─────────

TEST_CASE("evaluate_peer_binding: exact match short-circuits to ok (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // exact_ok=true means the strict check (or trusted-gateway) already passed —
    // no accommodation is consulted.
    CHECK(AgentServiceImpl::evaluate_peer_binding(true, "10.0.0.1", "10.0.0.1", false, {}) ==
          O::exact_ok);
    CHECK(AgentServiceImpl::evaluate_peer_binding(true, "10.0.0.1", "10.0.0.9", false, {}) ==
          O::exact_ok); // exact_ok is authoritative regardless of IP equality
}

TEST_CASE("evaluate_peer_binding: default (no accommodation) rejects a mismatch (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // Strict-by-default: no mTLS match, no trusted CIDR → a mismatch is reject.
    // This is the unchanged #826 behaviour and the cross-range replay guard.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "8.8.8.8", false, {}) ==
          O::reject);
    const std::vector<std::string> cidrs{"203.0.113.0/24"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "8.8.8.8", false, cidrs) ==
          O::reject); // only one side in range → still reject
    // #1128 acceptance bar "cross-range replay rejected" pinned at the decision
    // layer: each IP sits in a DIFFERENT trusted range, so they share none →
    // reject (a sniffed session replayed from another trusted subnet loses).
    const std::vector<std::string> two{"203.0.113.0/24", "198.51.100.0/24"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "198.51.100.7", false,
                                                  two) == O::reject);
}

TEST_CASE("evaluate_peer_binding: empty IP is always reject, accommodation cannot rescue (#1128)",
          "[agent_service][peer_mismatch][issue1128][issue826]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    const std::vector<std::string> cidrs{"0.0.0.0/0"};
    // #826: an empty extracted IP is a mismatch, never a wildcard — even with a
    // matching mTLS identity or an all-encompassing /0 trusted range.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "", "10.0.0.1", true, cidrs) == O::reject);
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "", true, cidrs) == O::reject);
}

TEST_CASE("evaluate_peer_binding: mTLS identity match downgrades to advisory (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // A verified, matching client identity is the stronger layer (#827/#1118),
    // so a multi-egress IP mismatch becomes advisory rather than reject.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "8.8.8.8",
                                                  /*client_identity_matches=*/true, {}) ==
          O::advisory_mtls);
    // mTLS takes precedence over CIDR when both would apply.
    const std::vector<std::string> cidrs{"0.0.0.0/0"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "10.0.0.2", true, cidrs) ==
          O::advisory_mtls);
}

TEST_CASE("evaluate_peer_binding: shared trusted CIDR downgrades to advisory (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    const std::vector<std::string> cidrs{"203.0.113.0/24", "2001:db8::/32"};
    // Legit multi-egress: both Register and Subscribe IPs in one declared range.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "203.0.113.200",
                                                  /*client_identity_matches=*/false, cidrs) ==
          O::advisory_nat_cidr);
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "2001:db8::1", "2001:db8:dead::beef", false,
                                                  cidrs) == O::advisory_nat_cidr);
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer round-trips, refuses empty",
          "[agent_service][peer_mismatch][issue826]") {
    // The trusted-gateway set is the second leg of the #826 fix —
    // gateway-mode Subscribe is allowed if the peer IP was previously
    // noted via ProxyRegister. Empty IP must NEVER round-trip (would
    // recreate the bypass).
    GatewayResponseHarness h;
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.2"));

    // Empty is rejected on insert AND on lookup.
    h.registry.note_trusted_gateway_peer("");
    CHECK_FALSE(h.registry.is_trusted_gateway_peer(""));
    // The original entry survives — the empty insert was a no-op,
    // not an accidental clear.
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
}

TEST_CASE("AgentRegistry::is_trusted_gateway_peer holds multiple gateways",
          "[agent_service][peer_mismatch][issue826]") {
    // A fleet may have multiple gateway nodes (load-balanced cluster).
    // Each gateway noted via ProxyRegister joins the trusted set; none
    // of them displaces another.
    GatewayResponseHarness h;
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    h.registry.note_trusted_gateway_peer("10.0.0.2");
    h.registry.note_trusted_gateway_peer("::1");
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.2"));
    CHECK(h.registry.is_trusted_gateway_peer("::1"));
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.3"));
}

// ── W1.3 R2 — trusted-gateway TTL + cap + gauge ────────────────────────────

TEST_CASE("AgentRegistry::is_trusted_gateway_peer evicts entries past TTL "
          "(W1.3 R2 / UP-3)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // UP-3: a stale entry (TTL elapsed) is no longer trusted. The lookup
    // returns false; the next note_trusted_gateway_peer sweeps it out of
    // the map.
    GatewayResponseHarness h;
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    REQUIRE(h.registry.trusted_gateway_peer_count() == 1);

    // Age past the TTL (1 h default) — push entries 2 h into the past.
    h.registry.expire_trusted_gateway_for_test(std::chrono::hours(2));

    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    // Map size unchanged until a new note triggers the sweep — the const
    // lookup path doesn't mutate.
    CHECK(h.registry.trusted_gateway_peer_count() == 1);

    // A fresh note from a DIFFERENT IP triggers the sweep that drops the
    // stale entry, then inserts the new one. Net size: 1 (not 2).
    h.registry.note_trusted_gateway_peer("10.0.0.2");
    CHECK(h.registry.trusted_gateway_peer_count() == 1);
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.2"));
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer refreshes last_seen on repeat "
          "(W1.3 R2)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // A gateway that re-ProxyRegisters before TTL elapses keeps its trust
    // entry alive indefinitely. Test: insert → age to JUST shy of TTL →
    // re-insert → age another half-TTL → still trusted (would have
    // expired without the refresh).
    GatewayResponseHarness h;
    h.registry.note_trusted_gateway_peer("10.0.0.1");

    // Age to 45 min (still within 1 h TTL).
    h.registry.expire_trusted_gateway_for_test(std::chrono::minutes(45));
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.1"));

    // Refresh.
    h.registry.note_trusted_gateway_peer("10.0.0.1");

    // Age another 45 min — without the refresh, total would be 90 min
    // (past TTL). With the refresh, last_seen reset to ~now, so this is
    // only 45 min from refresh → still trusted.
    h.registry.expire_trusted_gateway_for_test(std::chrono::minutes(45));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer caps map at kTrustedGatewayCap, "
          "evicts oldest first (W1.3 R2 / UP-2)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // UP-2: in a churn-heavy NAT environment the trusted set used to
    // grow unboundedly. The cap (1024) prevents memory DoS; oldest-first
    // eviction preserves trust for the most recent gateways.
    using yuzu::server::detail::AgentRegistry;
    GatewayResponseHarness h;

    // Fill to cap. We use distinct IPs to avoid the in-place refresh path.
    // Each insert is one steady_clock tick newer than the previous, so
    // "oldest" = the first IP inserted.
    for (std::size_t i = 0; i < AgentRegistry::kTrustedGatewayCap; ++i) {
        h.registry.note_trusted_gateway_peer("10.0." + std::to_string(i / 256) + "." +
                                             std::to_string(i % 256));
    }
    REQUIRE(h.registry.trusted_gateway_peer_count() == AgentRegistry::kTrustedGatewayCap);
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.0")); // first inserted

    // One more insert pushes the oldest entry out (not the new one, not a
    // middle one). Net size: cap, not cap+1.
    h.registry.note_trusted_gateway_peer("192.168.99.99");
    CHECK(h.registry.trusted_gateway_peer_count() == AgentRegistry::kTrustedGatewayCap);
    CHECK(h.registry.is_trusted_gateway_peer("192.168.99.99"));  // new entry kept
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.0")); // oldest evicted
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer updates the Prometheus gauge "
          "(W1.3 R2)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2][metrics]") {
    // The yuzu_trusted_gateway_peer_set_size gauge reflects current map
    // size on every note + every sweep, so dashboards see real-time
    // health (rising under churn, falling as entries expire).
    GatewayResponseHarness h;

    auto current_gauge = [&]() {
        return h.metrics.gauge("yuzu_trusted_gateway_peer_set_size").value();
    };

    CHECK(current_gauge() == 0.0); // gauge unset → 0

    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(current_gauge() == 1.0);

    h.registry.note_trusted_gateway_peer("10.0.0.2");
    h.registry.note_trusted_gateway_peer("10.0.0.3");
    CHECK(current_gauge() == 3.0);

    // Re-insert the same IP — refreshes last_seen, does not change size.
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(current_gauge() == 3.0);

    // Age all entries past TTL, then trigger a sweep via a fresh note —
    // gauge drops from 3 to 1 (3 expired + 1 new).
    h.registry.expire_trusted_gateway_for_test(std::chrono::hours(2));
    h.registry.note_trusted_gateway_peer("172.16.0.1");
    CHECK(current_gauge() == 1.0);
}

// ── W1.3 R2 — Fix #1 / UP-7 — trust-after-auth on ProxyRegister ────────────

TEST_CASE("ProxyRegister: failed enrollment (no token, no auto-approve) does NOT "
          "add the peer to the trusted set (W1.3 R2 / UP-7)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2][gateway]") {
    // UP-7 / sec-G MEDIUM-1: the trusted-peer noting used to fire BEFORE
    // the enrollment branches, with the rationale that even denied
    // proxies should contribute to gateway-trust discovery. That inverted
    // the trust model — any peer reaching :50055 with any payload became
    // trusted. The fix moves the noting to the post-`gw_enrolled:`
    // success path. With a fresh AuthManager and no auto-approve rules,
    // ProxyRegister falls into the "pending" branch (Tier 1 queue) and
    // returns without touching the trusted set.
    //
    // Note: context==nullptr in this test means the trust-noting branch
    // would skip even on success — what this test pins is structural:
    // the *pending* return doesn't add anything. The success-path counter-
    // example is the existing test
    // "AgentRegistry::note_trusted_gateway_peer round-trips, refuses empty"
    // which proves the helper itself is wired and reachable.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    GatewayResponseHarness h;
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-pending");
    req.mutable_info()->set_hostname("host-pending");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.mutable_info()->set_agent_version("0.0.0-test");
    // No enrollment_token, no auto-approve rules → Tier 1 pending branch.

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "pending");
    // The invariant under test: pending enrollment did not touch the
    // trusted set. (And the gauge stayed at 0.)
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
    CHECK(h.metrics.gauge("yuzu_trusted_gateway_peer_set_size").value() == 0.0);
}

TEST_CASE("ProxyRegister: invalid enrollment token does NOT add the peer to the "
          "trusted set (W1.3 R2 / UP-7)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2][gateway]") {
    // Companion to the pending-branch test above — the denied-token
    // branch in ProxyRegister also returns early without crossing into
    // the trust-noting code. Pre-fix this branch would have already
    // recorded the peer.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    GatewayResponseHarness h;
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-bad-token");
    req.mutable_info()->set_hostname("host-bad-token");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token("clearly-invalid-token");

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
}

// ── W1.3 R2 — Fix #3 / consistency MEDIUM-1 — shared peer_ip.hpp ───────────

TEST_CASE("peer_ip.hpp::extract_peer_ip matches AgentServiceImpl::extract_peer_ip "
          "byte-for-byte (W1.3 R2 / consistency MEDIUM-1)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // The two former call sites in agent_service_impl.cpp and
    // gateway_service_impl.cpp now route through the shared free function
    // in peer_ip.hpp. The static member AgentServiceImpl::extract_peer_ip
    // is a thin shim retained for the existing test surface. Pin: both
    // entry points produce identical output on every shape gRPC can hand
    // back.
    using yuzu::server::detail::AgentServiceImpl;
    using yuzu::server::detail::extract_peer_ip;

    const std::string_view inputs[] = {
        "ipv4:1.2.3.4:5678", "ipv4:127.0.0.1:50051",
        "ipv6:[::1]:50051",  "ipv6:[2001:db8::1]:443",
        "unix:/tmp/sock",    "",
        "garbage",           "ipv6:no-brackets:8080",
        "ipv6:[unclosed",
    };

    for (auto in : inputs) {
        CHECK(AgentServiceImpl::extract_peer_ip(in) == extract_peer_ip(in));
    }
}

// ── W1.4 R2 / UP-H1 — agent_id length cap at handler entry ─────────────────

TEST_CASE("Register: rejects oversize agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[agent_service][register][w1_4_r2][up_h1]") {
    // The protobuf places no length constraint on agent_id and W1.4 PR1
    // audits the value verbatim. Without this cap, a presenter can supply
    // a 1 MiB agent_id and every downstream audit row carries it. Cap is
    // checked BEFORE any audit emission, mTLS check, or auth-mgr lookup
    // so attack traffic costs ~one strlen + counter increment.
    using yuzu::server::auth::kMaxAgentIdLength;
    GatewayResponseHarness h;

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(std::string(kMaxAgentIdLength + 1, 'A'));
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    // Counter ticked with the right label.
    yuzu::Labels labels{{"reason", "length"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
}

TEST_CASE("Register: rejects empty agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[agent_service][register][w1_4_r2][up_h1]") {
    // Empty agent_id is structurally invalid — every downstream code path
    // assumes a non-empty key (registry, audit principal, pending lookup).
    // Same metric / status as the oversize case.
    GatewayResponseHarness h;

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("");
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    yuzu::Labels labels{{"reason", "length"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
}

TEST_CASE("ProxyRegister: rejects oversize agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[agent_service][register][gateway][w1_4_r2][up_h1]") {
    // Mirror of the direct-Register path. ProxyRegister carries the same
    // attack surface — the gateway proxies the agent's RegisterRequest
    // unmodified, so an attacker who controls the agent payload can
    // present an oversize agent_id here too. Source label on the metric
    // discriminates gateway-proxied attacks from direct-connect ones.
    using yuzu::server::auth::kMaxAgentIdLength;
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    GatewayResponseHarness h;
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(std::string(kMaxAgentIdLength + 1, 'B'));
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    yuzu::Labels labels{{"reason", "length"}, {"source", "gateway_proxy"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
    // Trusted-peer set untouched — the early-reject path never reaches
    // the post-success note_trusted_gateway_peer call.
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
}

// ── #872 — notify_exec_tracker wiring through to ExecutionTracker ──────────
//
// Bare GatewayResponseHarness leaves execution_tracker_ at nullptr, so the
// entire notify_exec_tracker body (5-status enum mapping, empty-execution_id
// early-return, null-tracker early-return) was dead in test. TrackerScope
// constructs a real in-memory ExecutionTracker and wires it via
// set_execution_tracker; destruction order is managed so the borrowed pointer
// in svc is nulled before the tracker destructs (mirrors the production
// shutdown contract documented at agent_service_impl.hpp:113).

namespace {

/// MEMBER ORDER LOAD-BEARING: members below are declared in the topological
/// order required by the dtor's three-phase shutdown — `db` is the raw
/// sqlite handle owned outright, `tracker` borrows it (via the
/// `ExecutionTracker(sqlite3*)` ctor), `svc` borrows `tracker.get()` (via
/// `set_execution_tracker`). The dtor MUST run set_execution_tracker(nullptr)
/// → tracker.reset() → sqlite3_close(db), in that exact order, so the
/// borrowed-pointer chain is unwound from the outside in. Reordering the
/// member declarations or replacing the user-defined dtor with `= default`
/// would silently break the contract — there is no compile-time guard.
/// Mirrors the production ServerImpl "drain gRPC → null setter → reset"
/// shutdown sequence at agent_service_impl.hpp:113.
struct TrackerScope {
    sqlite3* db{nullptr};
    std::unique_ptr<yuzu::server::ExecutionTracker> tracker;
    AgentServiceImpl* svc{nullptr};

    explicit TrackerScope(AgentServiceImpl& s) : svc(&s) {
        REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
        tracker = std::make_unique<yuzu::server::ExecutionTracker>(db);
        tracker->create_tables();
        svc->set_execution_tracker(tracker.get());
    }
    ~TrackerScope() {
        if (svc)
            svc->set_execution_tracker(nullptr);
        tracker.reset();
        if (db)
            sqlite3_close(db);
    }

    TrackerScope(const TrackerScope&) = delete;
    TrackerScope& operator=(const TrackerScope&) = delete;

    /// Create an execution row on the bound tracker, return its id. Matches
    /// the `GatewayResponseHarness::make_response` static-factory pattern —
    /// keeps test bodies focused on the assertion, not boilerplate. Call
    /// sites read `auto exec_id = ts.make_exec();`.
    std::string make_exec(int agents_targeted = 1) {
        yuzu::server::Execution exec;
        exec.definition_id = "def-test";
        exec.scope_expression = "agent_id = 'agent-1'";
        exec.dispatched_by = "tester";
        exec.status = "running";
        exec.agents_targeted = agents_targeted;
        auto id = tracker->create_execution(exec);
        REQUIRE(id.has_value());
        return *id;
    }
};

} // namespace

TEST_CASE("notify_exec_tracker: RUNNING maps to status='running' with "
          "completed_at=0",
          "[agent_service][executions][issue872]") {
    // RUNNING is the only non-terminal mapping in the switch — it stamps
    // first_response_at but leaves completed_at zero. A regression that
    // unifies the RUNNING and terminal branches (treating RUNNING as
    // completed) would flip executions to "done" on their first chunk.
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::RUNNING,
                                                      /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "running");
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at == 0);
}

TEST_CASE("notify_exec_tracker: SUCCESS maps to status='success' and stamps "
          "completed_at",
          "[agent_service][executions][issue872]") {
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].exit_code == 0);
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at > 0);
}

TEST_CASE("notify_exec_tracker: FAILURE preserves error_detail and exit_code",
          "[agent_service][executions][issue872]") {
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::FAILURE,
                                                      /*output=*/"", /*exit_code=*/3);
    resp.mutable_error()->set_message("plugin returned non-zero");
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].exit_code == 3);
    CHECK(statuses[0].error_detail == "plugin returned non-zero");
    CHECK(statuses[0].completed_at > 0);
}

TEST_CASE("notify_exec_tracker: TIMEOUT maps to status='timeout'",
          "[agent_service][executions][issue872]") {
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::TIMEOUT);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "timeout");
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at > 0);
    // notify_exec_tracker only populates s.error_detail when resp.has_error().
    // The TIMEOUT response was constructed with no error message, so the
    // resulting column must be empty — pins the has_error()==false arm of
    // the conditional at agent_service_impl.cpp:1157 against a regression
    // that copies the field unconditionally.
    CHECK(statuses[0].error_detail.empty());
}

TEST_CASE("notify_exec_tracker: REJECTED maps to status='rejected'",
          "[agent_service][executions][issue872]") {
    // notify_exec_tracker sets s.first_response_at=0 for REJECTED (the agent
    // rejected the command at dispatch, never began executing — "first
    // response" is conceptually undefined). The DB column still ends up
    // stamped to `now` because the bind layer substitutes
    // `s.first_response_at > 0 ? s.first_response_at : now`
    // (execution_tracker.cpp:363), making the struct-field zero invisible
    // to consumers.
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::REJECTED);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "rejected");
    CHECK(statuses[0].completed_at > 0);
    // Both first_response_at and completed_at derive from the same
    // `system_clock::now()` snapshot inside update_agent_status — first_response_at
    // via the bind-layer substitution, completed_at via the direct bind. They
    // are written from the same instant, so they cannot legitimately diverge
    // by more than ~1 second. A regression that stops substituting `now` for
    // a zero first_response_at would land first_response_at=0 vs
    // completed_at>1e9, blowing this bound — catches the specific drift the
    // bind-layer comment above warns about, without mocking the clock.
    CHECK(statuses[0].first_response_at >= statuses[0].completed_at - 1);
    CHECK(statuses[0].first_response_at <= statuses[0].completed_at + 1);
}

TEST_CASE("notify_exec_tracker: unmapped command_id is a no-op",
          "[agent_service][executions][issue872]") {
    // Out-of-band dispatch (CLI / direct gRPC) never calls record_execution_id.
    // notify_exec_tracker must early-return on empty execution_id rather than
    // upserting under a fabricated id — those rows would be invisible to every
    // tracker query (all filter by execution_id) but would still bloat the
    // table and break the documented "out-of-band = no tracker side effect"
    // contract referenced in agent_service_impl.cpp:1146.
    GatewayResponseHarness h;
    TrackerScope ts{h.svc};
    auto exec_id = ts.make_exec();
    // Deliberately do NOT call record_execution_id — cmd-orphan is unmapped.

    auto resp = GatewayResponseHarness::make_response("cmd-orphan", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    CHECK(ts.tracker->get_agent_statuses(exec_id).empty());
}

TEST_CASE("notify_exec_tracker: null tracker pointer is a no-op (shutdown contract)",
          "[agent_service][executions][issue872]") {
    // The atomic-load-acquire in notify_exec_tracker is the read half of the
    // shutdown contract — ServerImpl drains gRPC, calls
    // set_execution_tracker(nullptr) with release ordering, then resets the
    // owning unique_ptr. A refactor that drops the null guard (e.g. assumes
    // tracker stays non-null once set) would crash in the shutdown window.
    // Pinned explicitly via the set→unset path, not just the never-set path
    // every other GatewayResponseHarness test exercises implicitly.
    GatewayResponseHarness h;
    {
        TrackerScope ts{h.svc};
        // ~TrackerScope calls set_execution_tracker(nullptr) before destroying
        // the tracker, leaving svc.execution_tracker_ at nullptr.
    }
    h.svc.record_execution_id("cmd-A", "exec-42");

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS);
    // Must not crash, must not dereference the destroyed tracker.
    h.svc.process_gateway_response("agent-1", resp);
}

// ── #1067 — admin-denied agent must NOT consume an enrollment token ─────────

TEST_CASE("Register: admin-denied agent does not consume the enrollment token (#1067)",
          "[agent_service][register][enrollment][issue1067]") {
    // W1.4 UP-M3: the consume happened BEFORE the admin-deny check, so a denied
    // attacker burned a use of the token on every attempt — depleting a
    // max_uses=1 token until the legitimate agent could no longer enroll. The
    // early PendingStatus::denied check pre-empts the consume.
    GatewayResponseHarness h;
    auto raw =
        h.auth_mgr.create_enrollment_token("dos-test", /*max_uses=*/1, std::chrono::hours(1));

    // Mark the attacker's agent_id admin-denied.
    h.auth_mgr.add_pending_agent("denied-agent", "evil-host", "linux", "x86_64", "0.0.0-test");
    REQUIRE(h.auth_mgr.deny_pending_agent("denied-agent"));
    REQUIRE(h.auth_mgr.get_pending_status("denied-agent") ==
            yuzu::server::auth::PendingStatus::denied);

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("denied-agent");
    req.mutable_info()->set_hostname("evil-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    // gov #1134: the denied rejection emits the bounded SIEM-routed counter.
    CHECK(h.metrics
              .counter("yuzu_register_denied_total",
                       {{"source", "direct"}, {"event", "security"}})
              .value() == 1.0);

    // Core invariant: the denied attempt did NOT consume the token.
    auto tokens = h.auth_mgr.list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 0);

    // And the single use is still available to a legitimate agent — proving the
    // max_uses=1 token was not depleted by the denied attacker.
    auto claim = h.auth_mgr.consume_enrollment_token(raw, "good-agent");
    CHECK(claim.has_value());
}

// ── #1065 — success-path enrollment audit is emitted (was fire-and-forget) ──

TEST_CASE("Register: successful token enrollment emits a success audit row (#1065)",
          "[agent_service][register][enrollment][audit][issue1065]") {
    GatewayResponseHarness h;
    auto raw =
        h.auth_mgr.create_enrollment_token("ok-test", /*max_uses=*/1, std::chrono::hours(1));

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("enroll-ok");
    req.mutable_info()->set_hostname("good-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.mutable_info()->set_agent_version("0.0.0-test");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    REQUIRE(h.svc.Register(/*context=*/nullptr, &req, &resp).ok());
    CHECK(resp.accepted());

    // The success-path audit row is now captured + persisted (#1065). Find it
    // by its stable fields rather than the action constant.
    auto rows = h.audit.query({});
    bool found = false;
    for (const auto& ev : rows) {
        if (ev.action == "enrollment.token_consumed" && ev.result == "success" &&
            ev.principal == "agent:enroll-ok" && ev.target_type == "enrollment_token") {
            found = true;
            break;
        }
    }
    CHECK(found);
}

TEST_CASE("ProxyRegister: admin-denied agent does not consume the enrollment token (#1067)",
          "[agent_service][register][enrollment][gateway][issue1067]") {
    // Sibling of the direct-Register #1067 test. The gateway ProxyRegister path
    // proxies the agent's RegisterRequest unmodified and had the same
    // consume-before-deny ordering — so the token-depletion DoS was equally
    // reachable here until the early PendingStatus::denied check was mirrored.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    GatewayResponseHarness h;
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    gateway_svc.set_audit_store(&h.audit);
    auto raw =
        h.auth_mgr.create_enrollment_token("gw-dos-test", /*max_uses=*/1, std::chrono::hours(1));
    h.auth_mgr.add_pending_agent("gw-denied", "evil-host", "linux", "x86_64", "0.0.0-test");
    REQUIRE(h.auth_mgr.deny_pending_agent("gw-denied"));

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("gw-denied");
    req.mutable_info()->set_hostname("evil-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    CHECK(h.metrics
              .counter("yuzu_register_denied_total",
                       {{"source", "gateway_proxy"}, {"event", "security"}})
              .value() == 1.0);
    auto tokens = h.auth_mgr.list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 0); // token not depleted via the gateway path

    // The single use is still available — proving non-depletion via the gateway
    // path too (symmetry with the direct-Register #1067 test).
    auto gw_claim = h.auth_mgr.consume_enrollment_token(raw, "good-gw-agent");
    CHECK(gw_claim.has_value());
}

// ── #1064 — ProxyRegister origin-IP attribution ─────────────────────────────

TEST_CASE("ProxyRegister: audit attributes the agent origin IP, not the gateway IP (#1064)",
          "[agent_service][register][enrollment][gateway][issue1064]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    GatewayResponseHarness h;
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    gateway_svc.set_audit_store(&h.audit);

    // An INVALID enrollment token drives the denied/failure audit site — where
    // the #1064 attribution records source_ip=agent origin + gateway_ip in
    // detail. context is nullptr (as in every ProxyRegister test) so the gateway
    // transport IP is empty; the attribution then comes ENTIRELY from
    // gateway_observed_peer, making the agent-vs-gateway distinction observable.
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("gw-origin-test");
    req.mutable_info()->set_hostname("agent-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token("no-such-token-xyz");
    apb::RegisterResponse resp;

    auto failure_row = [&]() -> yuzu::server::AuditEvent {
        for (const auto& ev : h.audit.query({})) {
            if (ev.result == "failure")
                return ev;
        }
        return {};
    };

    SECTION("origin observed → source_ip is the agent IP, not the gateway") {
        req.set_gateway_observed_peer("203.0.113.7");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        CHECK_FALSE(resp.accepted());
        const auto row = failure_row();
        CHECK(row.source_ip == "203.0.113.7"); // agent origin — the core attribution proof
        // gateway_ip key is always recorded; its VALUE is empty here only
        // because the test passes context=nullptr (no transport peer). With a
        // real context it would carry the gateway's IP. source_ip above is the
        // assertion that proves agent-origin vs gateway attribution.
        CHECK(row.detail.find("gateway_ip=") != std::string::npos);
        CHECK(row.detail.find("origin_observed=false") == std::string::npos);
    }

    SECTION("origin absent → falls back to gateway IP, flagged origin_observed=false") {
        // No gateway_observed_peer set; null context → gateway IP empty.
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        const auto row = failure_row();
        CHECK(row.source_ip.empty()); // gateway-IP fallback (empty under null ctx)
        CHECK(row.detail.find("origin_observed=false") != std::string::npos);
    }

    SECTION("malformed origin is rejected by the strict parser → fallback") {
        // A non-IP value (incl. an injection attempt) must NOT round-trip into
        // the audit row — normalize_bare_ip returns empty, so we fall back.
        req.set_gateway_observed_peer("1.2.3.4; rm -rf /");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        const auto row = failure_row();
        CHECK(row.source_ip.empty());
        CHECK(row.detail.find("origin_observed=false") != std::string::npos);
        CHECK(row.detail.find("rm -rf") == std::string::npos); // no junk in evidence
    }

    SECTION("success path also attributes the agent origin (gov QE SHOULD)") {
        // The success audit site (valid token → accepted) shares append_origin_detail.
        auto raw = h.auth_mgr.create_enrollment_token("gw-origin-test", /*max_uses=*/1,
                                                      std::chrono::hours(1));
        req.set_enrollment_token(raw);
        req.set_gateway_observed_peer("203.0.113.9");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        CHECK(resp.accepted());
        yuzu::server::AuditEvent success_row;
        for (const auto& ev : h.audit.query({})) {
            if (ev.result == "success")
                success_row = ev;
        }
        CHECK(success_row.source_ip == "203.0.113.9"); // agent origin on the success row too
        CHECK(success_row.detail.find("gateway_ip=") != std::string::npos);
    }
}
