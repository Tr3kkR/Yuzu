/**
 * test_store_wiring_order.cpp -- #3261 regression guard: every
 * `agent_service_.set_X(member_.get())` / `gateway_service_->set_X(member_.get())`
 * call in server.cpp must run AFTER `member_`'s construction, never before.
 *
 * WHY THIS GUARD EXISTS. #3261: a wiring block ran at the top of the
 * ServerImpl constructor, guarded by `if (notification_store_)` /
 * `if (webhook_store_)` / `if (offload_target_store_)` -- but each of those
 * three members was constructed ~650 lines LATER in the same constructor.
 * The guards were unique_ptr members default-initialised to null, so they
 * were guaranteed-false on every boot, not merely racy: dashboard
 * notifications, webhook delivery, and response offload from the
 * AgentServiceImpl paths (Register / Subscribe / process_gateway_response)
 * were silently dead for the life of the process. Every use site
 * double-guards `ptr && ptr->is_open()` with silent skip, so nothing logged
 * or alerted -- the bug produced zero signal. A source-scan guard is the
 * only thing that would have caught it, because ServerImpl is not
 * unit-constructible (see test_default_certs.cpp's note that boot ordering
 * is exercised only by a live boot test, external to this suite).
 *
 * MECHANISM -- no hand-copied member list. This test opens server.cpp (via
 * `YUZU_SERVER_SRC_DIR`, injected by tests/meson.build) AT TEST RUN TIME and
 * regex-scans the raw source text for:
 *   - every `agent_service_.set_X(member_.get())` / `gateway_service_->
 *     set_X(member_.get())` call (the setter-call regex captures the member
 *     name from its `.get()` argument, so no separate list of members needs
 *     maintaining); and
 *   - every `member_ = std::make_unique<...>` construction.
 * For each setter call at line L wiring member M, the rule is: some
 * construction of M exists, and the EARLIEST such construction is on a line
 * strictly before L. Every member matched by the setter regex has exactly
 * one `std::make_unique` site today (verified at the time this test was
 * written) -- "earliest" is the chosen semantic for the day a member ever
 * gains a second construction site (e.g. a reconfigure/rebuild path).
 *
 * `//` line comments are stripped before scanning, defensively -- verified
 * at the time of writing that server.cpp's match counts are IDENTICAL with
 * and without stripping (no setter or construction call is presently
 * mentioned only inside a comment), so this costs nothing today and guards
 * against a future false match/miss inside commented-out code.
 *
 * EXCLUDED BY THE REGEX, NOT BY AN ALLOWLIST: by-reference setter forms
 * (`set_health_store(&health_store_)`, `set_blast_radius_detector(&blast_
 * radius_detector_)`) since they take `&member_`, not `member_.get()`; every
 * `set_X(nullptr)` shutdown null-out in `stop()`, since `nullptr` is not
 * `\w+_\.get()`; and local-variable / config-value setters (e.g.
 * `set_agent_cert_signer(cert_signer)`), since the argument is not of the
 * form `<name>_.get()` bound to a `std::make_unique<...>`-constructed
 * member. A member wired from a helper or a non-`make_unique` factory would
 * be invisible to the construction regex; there are none in server.cpp
 * today (no `.reset(new` / `= std::unique_ptr<` assignment exists there),
 * and the sanity floor below fails loudly if the setter side of the scan
 * ever drifts to near-zero.
 *
 * A member wired anywhere in server.cpp -- new file location aside, since
 * this scan is server.cpp-specific, matching where every setter/construction
 * call for these three stores and their 25 correctly-ordered siblings
 * presently lives -- is picked up automatically on the next test run.
 * Nothing here needs updating when a setter or construction call is added
 * in the correct order; a failure means an ordering regression was
 * introduced, not that this file is stale.
 *
 * WHAT THIS SCAN DOES NOT CATCH (governance Gate 3 architect + quality-
 * engineer, both SHOULD, recorded here per docs-writer-owns-wording /
 * domain-agent-owns-truth so a reader trusts the guarantee this test
 * actually gives, not a stronger one):
 *   - A setter wired to the WRONG member, e.g. `set_webhook_store(
 *     offload_target_store_.get())`. The scan ties correctness to whichever
 *     member name literally appears in the call; it has no notion of which
 *     member a given setter is SUPPOSED to receive.
 *   - A setter or construction inside a branch that is never taken at
 *     runtime (dead code, an always-false `if`). This is pure text-position
 *     scanning with no control-flow awareness -- a setter genuinely gated on
 *     a runtime condition (e.g. NotificationStore's PG-fail-closed branch)
 *     is indistinguishable, from the regex's point of view, from one that
 *     can never execute at all.
 *   - PRESENCE. The order check only fires for setters that exist; deleting
 *     a setter (and its member's construction) outright does not fail this
 *     test as long as >= 25 setters remain (see the sanity floor below) --
 *     see the second TEST_CASE in this file, which pins presence of the
 *     three specific #3261 setters explicitly, for exactly this reason.
 *   - Only single-line `//`-style comments are stripped before scanning --
 *     C-style block comments are NOT stripped. Empirically harmless today
 *     (no setter or construction call is presently written inside one), and
 *     deliberately left unstripped rather than "fixed" with a naive
 *     block-comment-matching regex -- an early attempt at exactly that
 *     swallowed real code by opening a phantom block comment inside a
 *     string literal elsewhere in server.cpp that happens to contain a
 *     slash-star-shaped substring, losing ~2000 real lines including 5 live
 *     setters from the scan. A correct fix needs a string-literal-aware
 *     stripper, which this file does not attempt.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

namespace {

namespace fs = std::filesystem;

struct SetterCall {
    int line;
    std::string receiver; // "agent_service_" or "gateway_service_"
    std::string setter;   // e.g. "notification_store"
    std::string member;   // e.g. "notification_store_"
};

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

/// `agent_service_.set_X(member_.get())` / `gateway_service_->set_X(member_.get())`.
/// Group 1: receiver (the trailing `.`/`->` is stripped off below so both
/// spellings compare equal). Group 2: setter suffix. Group 3: member name.
std::vector<SetterCall> extract_setter_calls(const std::string& text) {
    static const std::regex re(
        R"regex(\b(agent_service_\.|gateway_service_->)set_(\w+)\(\s*(\w+_)\.get\(\)\s*\))regex");
    std::vector<SetterCall> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        const std::string raw_receiver = m[1].str();
        const std::string receiver =
            raw_receiver == "agent_service_." ? "agent_service_" : "gateway_service_";
        out.push_back(
            {line_of(text, static_cast<std::size_t>(m.position(0))), receiver, m[2].str(), m[3].str()});
    }
    return out;
}

/// `member_ = std::make_unique<...>`. Returns every construction line per
/// member (a member with more than one site keeps every line; the rule
/// checked below uses the earliest).
std::map<std::string, std::vector<int>> extract_constructions(const std::string& text) {
    static const std::regex re(R"regex(\b(\w+_)\s*=\s*std::make_unique<)regex");
    std::map<std::string, std::vector<int>> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        out[m[1].str()].push_back(line_of(text, static_cast<std::size_t>(m.position(0))));
    }
    return out;
}

std::string strip_line_comments(const std::string& text) {
    static const std::regex re(R"(//[^\n]*)");
    return std::regex_replace(text, re, "");
}

} // namespace

TEST_CASE("server.cpp: every agent_service_/gateway_service_ store setter runs after "
          "its member's construction (#3261)",
          "[wiring_order]") {
    const std::string text = strip_line_comments(read_server_cpp());
    const auto setters = extract_setter_calls(text);
    const auto constructions = extract_constructions(text);

    // Sanity floor: measured 28 setter calls against server.cpp at the time
    // this test was written. A near-zero count means the SCAN is broken (a
    // receiver/method spelling drifted, or YUZU_SERVER_SRC_DIR points
    // somewhere unexpected), not that the wired-store surface shrank to
    // nothing -- fail loud rather than pass vacuously.
    REQUIRE(setters.size() >= 25);

    for (const auto& s : setters) {
        INFO("setter " << s.receiver << ".set_" << s.setter << "(" << s.member
                        << ".get()) at server.cpp:" << s.line);
        auto it = constructions.find(s.member);
        const bool has_construction = it != constructions.end() && !it->second.empty();
        CHECK(has_construction);
        if (!has_construction)
            continue;
        const int earliest_construction = *std::min_element(it->second.begin(), it->second.end());
        INFO("earliest construction of " << s.member << " at server.cpp:" << earliest_construction);
        CHECK(earliest_construction < s.line);
    }
}

TEST_CASE("server.cpp: the three #3261 setters specifically are still present "
          "(#3261 presence pin)",
          "[wiring_order]") {
    // Companion to the ordering test above (quality-engineer SHOULD, Gate
    // 3): that test only asserts ORDER for whatever setters happen to
    // exist, gated by a >= 25 sanity floor. Deleting all three of
    // #3261's setters outright (28 - 3 = 25) would still clear that
    // floor and pass silently -- exactly the literal symptom #3261 was.
    // Pin presence of these three explicitly so that regression can never
    // hide behind the floor.
    const std::string text = strip_line_comments(read_server_cpp());
    const auto setters = extract_setter_calls(text);

    auto has = [&](const char* receiver, const char* setter, const char* member) {
        return std::any_of(setters.begin(), setters.end(), [&](const SetterCall& s) {
            return s.receiver == receiver && s.setter == setter && s.member == member;
        });
    };
    CHECK(has("agent_service_", "notification_store", "notification_store_"));
    CHECK(has("agent_service_", "webhook_store", "webhook_store_"));
    CHECK(has("agent_service_", "offload_target_store", "offload_target_store_"));
}

// #1712 branch-review finding (Functional CDX-FV-01, HIGH): the production
// Response:Read visibility resolver `response_visible_set_fn` (defined
// ~server.cpp:16819, wired into DashboardRoutes::register_routes as its
// trailing argument ~server.cpp:18401) is referenced by ZERO test files --
// every dashboard route test injects its own synthetic VisibleSetFn. Dropping
// the production registration argument (e.g. reverting to the pre-#1712
// call, or replacing it with `{}`) would restore fleet-wide facet/scope
// disclosure in production while every existing #1712 test stayed green,
// because none of them exercise this composition. Following this file's own
// established mechanism (ServerImpl is not unit-constructible, so a source
// scan is the only thing that can catch a dropped composition at all) rather
// than inventing a second one.
TEST_CASE("server.cpp: response_visible_set_fn is both defined and passed to "
          "DashboardRoutes::register_routes (#1712)",
          "[wiring_order][1712]") {
    const std::string text = strip_line_comments(read_server_cpp());

    // Sanity floor: server.cpp is a six-figure-character file; a
    // suspiciously short read means YUZU_SERVER_SRC_DIR pointed somewhere
    // empty or mangled, not that the file legitimately shrank.
    REQUIRE(text.size() > 100000);

    // POSITIVE anchor 1: the resolver is defined, and its body is the real
    // decision ladder -- not a stub that always returns nullopt/fleet-wide.
    // Requiring both calls it actually makes (not just its name) means a
    // resolver silently downgraded to "return std::nullopt;" still fails
    // this, even though `response_visible_set_fn` itself would still exist.
    static const std::regex definition_re(R"(auto response_visible_set_fn =)");
    CHECK(std::regex_search(text, definition_re));
    static const std::regex global_check_re(
        R"(check_permission\(username, "Response", "Read"\))");
    CHECK(std::regex_search(text, global_check_re));
    static const std::regex scoped_check_re(
        R"(visible_agents_for_permission\(username, "Response", "Read")");
    CHECK(std::regex_search(text, scoped_check_re));

    // POSITIVE anchor 2: the resolver is actually PASSED to
    // register_routes, not merely defined and left unused. This is what
    // distinguishes "wired" from "defined but dropped at the call site" --
    // the failure mode a name-presence-only check would miss entirely. The
    // optional `std::move(...)` wrapper is tolerated -- moving the callback
    // into the by-value `VisibleSetFn` parameter is the correct idiom (it's
    // never used again after this call) and must not make this anchor a
    // false negative.
    static const std::regex wired_re(
        R"(,\s*(?:std::move\()?response_visible_set_fn\)?\s*\))");
    CHECK(std::regex_search(text, wired_re));

    // Exactly two occurrences of the identifier total: one definition, one
    // use. A THIRD occurrence would mean a second, possibly divergent, copy
    // was introduced somewhere -- this codebase's established anti-pattern
    // this test's own file header (and response_scope_filter.hpp elsewhere)
    // explicitly warns against duplicating a chokepoint like this one.
    static const std::regex occurrence_re(R"(\bresponse_visible_set_fn\b)");
    auto count = static_cast<std::ptrdiff_t>(
        std::distance(std::sregex_iterator(text.begin(), text.end(), occurrence_re),
                      std::sregex_iterator()));
    CHECK(count == 2);
}
