/**
 * test_shutdown_join_order.cpp -- #3495 regression guard: ServerImpl::stop()
 * must call agent_server_->Shutdown(deadline) BEFORE joining any background
 * thread that can be blocked inside AgentRegistry::send_to() ->
 * stream->Write() (pre-flight runner, quarantine containment reconciler,
 * schedule tick).
 *
 * WHY THIS GUARD EXISTS. All three of those threads synchronously call into
 * a gRPC stream write with no bound of its own -- it can stall indefinitely
 * on an HTTP/2 flow-control window. `agent_server_->Shutdown(deadline)` is
 * the ONLY thing in `stop()` that forcibly cancels such a write. Before
 * #3495, Shutdown(deadline) ran AFTER the three joins, so a thread blocked
 * inside a write had no path to unblock: a normal SIGTERM had no in-process
 * timed escalation for this case, so `stop()` could hang until an external
 * SIGKILL (e.g. Kubernetes' post-grace-period kill) arrived, losing the
 * final audit/evidence rows for whatever was in flight and skipping every
 * later teardown step. Found via governance #3495 (chaos-injector HIGH +
 * codex external tie-break, 2026-08-24) on the same three-thread shape #3042
 * and #3007 already document for other components.
 *
 * MECHANISM -- no hand-copied line numbers. This test opens server.cpp (via
 * `YUZU_SERVER_SRC_DIR`, injected by tests/meson.build) AT TEST RUN TIME and
 * locates, by regex, the single call sites for:
 *   - `agent_server_->Shutdown(deadline)`
 *   - `preflight_runner_thread_.join()`
 *   - `quarantine_reconcile_thread_.join()`
 *   - `schedule_tick_thread_.join()`
 *   - `heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr)`
 * then asserts Shutdown's line number is strictly BEFORE each of the three
 * joins', and strictly BEFORE the fn-null wait's (re-verifying the #3495
 * acceptance criterion that this wait's already-bounded shape must not
 * regress to unbounded when the reorder lands).
 *
 * Same technique and same rationale as test_store_wiring_order.cpp's #3261
 * guard: `ServerImpl` is not unit-constructible (see test_default_certs.cpp),
 * so a source-scan is the only thing that catches an ordering regression in
 * a function this large without standing up a live gRPC server and
 * deliberately stalling a stream write (issue #3495's own suggested-scope
 * item 6 notes that would need an integration or TSan-assisted test, not a
 * unit test -- this guard covers the ordering property directly instead).
 *
 * WHAT THIS SCAN DOES NOT CATCH: that Shutdown's 5s deadline is itself
 * sufficient in practice, that the join actually completes once cancellation
 * lands, or any change to whichever OTHER statements sit between these call
 * sites. It proves relative source order only -- exactly the property that
 * regressed once already (the joins predate Shutdown's call site by ~150
 * lines before this fix).
 */

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

namespace {

namespace fs = std::filesystem;

std::string read_server_cpp() {
    const fs::path path = fs::path(YUZU_SERVER_SRC_DIR) / "server.cpp";
    REQUIRE(fs::is_regular_file(path));
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int line_of(const std::string& text, std::size_t pos) {
    return static_cast<int>(std::count(text.begin(), text.begin() + static_cast<long>(pos), '\n')) +
           1;
}

std::string strip_line_comments(const std::string& text) {
    static const std::regex re(R"(//[^\n]*)");
    return std::regex_replace(text, re, "");
}

// Returns the line number of the FIRST match, failing loudly (rather than
// returning an empty optional silently) if the pattern isn't found -- a
// vacuous pass here would be worse than a hard failure, since it would mean
// the scan itself broke, not that the ordering is fine.
int require_one_line(const std::string& text, const std::regex& re, const char* label) {
    std::smatch m;
    INFO("looking for: " << label);
    REQUIRE(std::regex_search(text, m, re));
    return line_of(text, static_cast<std::size_t>(m.position(0)));
}

} // namespace

TEST_CASE("server.cpp: agent_server_->Shutdown(deadline) runs before the pre-flight/"
          "quarantine/schedule joins and the heartbeat fn-null wait (#3495)",
          "[shutdown_order]") {
    const std::string text = strip_line_comments(read_server_cpp());

    const int shutdown_line =
        require_one_line(text, std::regex(R"(agent_server_->Shutdown\(deadline\))"),
                          "agent_server_->Shutdown(deadline)");
    const int preflight_join_line = require_one_line(
        text, std::regex(R"(preflight_runner_thread_\.join\(\))"), "preflight_runner_thread_.join()");
    const int quarantine_join_line =
        require_one_line(text, std::regex(R"(quarantine_reconcile_thread_\.join\(\))"),
                          "quarantine_reconcile_thread_.join()");
    const int schedule_join_line = require_one_line(
        text, std::regex(R"(schedule_tick_thread_\.join\(\))"), "schedule_tick_thread_.join()");
    const int fn_null_wait_line =
        require_one_line(text, std::regex(R"(heartbeat_ingestion_->set_quarantine_reconcile_fn\(nullptr\))"),
                          "heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr)");

    INFO("Shutdown(deadline) at server.cpp:" << shutdown_line);
    INFO("preflight_runner_thread_.join() at server.cpp:" << preflight_join_line);
    CHECK(shutdown_line < preflight_join_line);

    INFO("quarantine_reconcile_thread_.join() at server.cpp:" << quarantine_join_line);
    CHECK(shutdown_line < quarantine_join_line);

    INFO("schedule_tick_thread_.join() at server.cpp:" << schedule_join_line);
    CHECK(shutdown_line < schedule_join_line);

    // #3495 acceptance criterion: the fn-null wait's already-bounded shape
    // (Shutdown's deadline plus whatever store-call timeout was already in
    // flight) must not regress to unbounded -- it stays sequenced after
    // Shutdown regardless of where the three joins above land relative to it.
    INFO("heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr) at server.cpp:"
         << fn_null_wait_line);
    CHECK(shutdown_line < fn_null_wait_line);
}
