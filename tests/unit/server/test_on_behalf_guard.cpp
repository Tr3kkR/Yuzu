// ADR-0022 Interim rules (execution-plan PR 1.1) — reserved on-behalf-of key
// guard. These tests pin the reserved-name set, the case-insensitive exact
// match the HTTP pre-routing chokepoint and the gRPC interceptor both rely
// on, the name-vs-value distinction, the log sanitizer, and the rejection
// counter.

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <string>
#include <utility>

#include <httplib.h>

#include "on_behalf_guard.hpp"
#include "yuzu/metrics.hpp"

using yuzu::server::onbehalf::find_reserved_key;
using yuzu::server::onbehalf::is_reserved_key;
using yuzu::server::onbehalf::kReservedKeys;
using yuzu::server::onbehalf::match_reserved_key;
using yuzu::server::onbehalf::note_rejection;
using yuzu::server::onbehalf::sanitize_for_log;

TEST_CASE("every reserved key matches itself and its uppercase form", "[onbehalf][adr0022]") {
    for (auto key : kReservedKeys) {
        CHECK(is_reserved_key(key));
        std::string upper{key};
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        CHECK(is_reserved_key(upper));
        // The canonical spelling returned is the reserved-list entry itself.
        auto hit = match_reserved_key(upper);
        REQUIRE(hit.has_value());
        CHECK(*hit == key);
    }
}

TEST_CASE("non-reserved names do not match", "[onbehalf][adr0022]") {
    CHECK_FALSE(is_reserved_key("authorization"));
    CHECK_FALSE(is_reserved_key("x-yuzu-token"));
    CHECK_FALSE(is_reserved_key("x-correlation-id"));
    // Prefix / suffix near-misses must not match: the guard rejects exact
    // reserved names, not a substring family.
    CHECK_FALSE(is_reserved_key("x-on-behalf-of-extra"));
    CHECK_FALSE(is_reserved_key("on-behalf"));
    CHECK_FALSE(is_reserved_key(""));
}

TEST_CASE("find_reserved_key scans httplib headers case-insensitively",
          "[onbehalf][adr0022]") {
    httplib::Headers clean{{"Authorization", "Bearer tok"}, {"Accept", "application/json"}};
    CHECK_FALSE(find_reserved_key(clean).has_value());

    httplib::Headers dirty{{"Authorization", "Bearer tok"},
                           {"X-Yuzu-On-Behalf-Of", "alice"}};
    auto hit = find_reserved_key(dirty);
    REQUIRE(hit.has_value());
    // Canonical lowercase spelling is returned for logging — never the value.
    CHECK(*hit == "x-yuzu-on-behalf-of");
}

TEST_CASE("reserved string in a header VALUE does not trigger", "[onbehalf][adr0022]") {
    // The scan matches NAMES only — a future refactor to substring/regex
    // scanning must not silently widen this to values.
    httplib::Headers h{{"X-Custom", "on-behalf-of=alice"},
                       {"Referer", "https://x/on-behalf-of"},
                       {"Cookie", "x-yuzu-on-behalf-of=1"}};
    CHECK_FALSE(find_reserved_key(h).has_value());
}

TEST_CASE("duplicate and empty-valued reserved headers still match",
          "[onbehalf][adr0022]") {
    httplib::Headers dup{{"On-Behalf-Of", "a"}, {"On-Behalf-Of", "b"}};
    CHECK(find_reserved_key(dup).has_value());
    httplib::Headers empty_val{{"x-yuzu-delegated-operator", ""}};
    CHECK(find_reserved_key(empty_val).has_value());
}

TEST_CASE("find_reserved_key catches the bare and generic spellings",
          "[onbehalf][adr0022]") {
    for (auto name : {"On-Behalf-Of", "x-on-behalf-of", "X-Yuzu-Delegated-Operator",
                      "x-yuzu-delegation-artifact"}) {
        httplib::Headers h{{name, "someone"}};
        INFO(name);
        CHECK(find_reserved_key(h).has_value());
    }
}

TEST_CASE("sanitize_for_log strips control chars and caps length",
          "[onbehalf][adr0022]") {
    CHECK(sanitize_for_log("/api/v1/devices") == "/api/v1/devices");
    // Percent-decoded newline / CR / NUL must not survive into a log line.
    CHECK(sanitize_for_log("/a\nFORGED: line") == "/a?FORGED: line");
    CHECK(sanitize_for_log(std::string_view{"\r\n\x00\x1b\x7f", 5}) == "?????");
    auto long_in = std::string(500, 'x');
    auto capped = sanitize_for_log(long_in);
    CHECK(capped.size() == 203);  // 200 + "..."
    CHECK(capped.ends_with("..."));
}

TEST_CASE("note_rejection counts every event and throttles logging",
          "[onbehalf][adr0022]") {
    yuzu::MetricsRegistry reg;
    // Pre-seeded-then-incremented: counter records every call regardless of
    // the log decision. (The throttle counters are process-global statics, so
    // this test asserts periodicity, not absolute phase.)
    auto& counter = reg.counter("yuzu_onbehalf_rejected_total",
                                {{"surface", "http"}, {"event", "security"}});
    auto before = counter.value();
    int logged = 0;
    for (int i = 0; i < 250; ++i) {
        if (note_rejection(reg, "http")) ++logged;
    }
    CHECK(counter.value() == before + 250);
    // Exactly every kLogEvery-th call logs: 250 calls see 2 or 3 log slots
    // depending on the global counter's phase.
    CHECK(logged >= 2);
    CHECK(logged <= 3);
}
