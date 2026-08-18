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
