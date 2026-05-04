/**
 * test_visualization_engine.cpp — unit coverage for the response-visualization
 * engine introduced in issue #253 (Phase 8.1).
 *
 * Exercises every (processor × chart_type) the engine ships, plus the
 * defensive paths the route handler relies on:
 *   - empty / "{}" spec → ok=false, "no visualization configured"
 *   - malformed JSON spec → ok=false
 *   - unknown processor / unknown chart type → ok=false
 *   - empty response set → ok=true with zero-length labels & series
 *   - max_categories cap collapses tail into "Other"
 *
 * The engine is pure data transformation, so the harness builds StoredResponse
 * vectors directly rather than standing up a ResponseStore.
 */

#include "result_parsing.hpp"
#include "response_store.hpp"
#include "visualization_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

StoredResponse make_resp(const std::string& agent, const std::string& output,
                         int status = 0, int64_t timestamp = 0) {
    StoredResponse r;
    r.agent_id = agent;
    r.output = output;
    r.status = status;
    r.timestamp = timestamp;
    return r;
}

} // namespace

TEST_CASE("VisualizationEngine: empty spec → no visualization", "[visualization][engine]") {
    VisualizationEngine eng;
    CHECK_FALSE(VisualizationEngine::has_visualization(""));
    CHECK_FALSE(VisualizationEngine::has_visualization("{}"));
    CHECK_FALSE(VisualizationEngine::has_visualization("[]"));
    auto r = eng.transform("", "processes", {});
    CHECK_FALSE(r.ok);
    CHECK(r.json.find("no visualization") != std::string::npos);
}

TEST_CASE("VisualizationEngine: count() handles object, array, empty (#587)",
          "[visualization][engine][multi_chart]") {
    CHECK(VisualizationEngine::count("") == 0);
    CHECK(VisualizationEngine::count("{}") == 0);
    CHECK(VisualizationEngine::count("[]") == 0);
    CHECK(VisualizationEngine::count(R"({"type":"pie","processor":"single_series"})") == 1);
    CHECK(VisualizationEngine::count(R"([{"type":"pie","processor":"single_series"}])") == 1);
    CHECK(VisualizationEngine::count(
        R"([{"type":"pie","processor":"single_series"},
             {"type":"bar","processor":"single_series"}])") == 2);
    // Non-object array entries (null, scalar) are filtered out
    CHECK(VisualizationEngine::count(
        R"([{"type":"pie","processor":"single_series"},null,42,
            {"type":"bar","processor":"single_series"}])") == 2);
    // Object missing required keys is not a chart
    CHECK(VisualizationEngine::count(R"([{"type":"pie"}])") == 0);
}

TEST_CASE("VisualizationEngine: transform_at picks the right chart (#587)",
          "[visualization][engine][multi_chart]") {
    VisualizationEngine eng;
    auto spec = R"([
        {"type":"pie","processor":"single_series","labelField":1,"title":"A"},
        {"type":"bar","processor":"single_series","labelField":2,"title":"B"}
    ])";
    std::vector<StoredResponse> responses{make_resp("a1",
        "1|chrome|/usr/bin/chrome|d")};

    auto r0 = eng.transform_at(spec, 0, "procfetch", responses);
    REQUIRE(r0.ok);
    auto j0 = nlohmann::json::parse(r0.json);
    CHECK(j0["chart_type"] == "pie");
    CHECK(j0["title"] == "A");

    auto r1 = eng.transform_at(spec, 1, "procfetch", responses);
    REQUIRE(r1.ok);
    auto j1 = nlohmann::json::parse(r1.json);
    CHECK(j1["chart_type"] == "bar");
    CHECK(j1["title"] == "B");

    // Out-of-range
    auto r_oor = eng.transform_at(spec, 2, "procfetch", responses);
    CHECK_FALSE(r_oor.ok);
    CHECK(r_oor.json.find("out of range") != std::string::npos);

    // transform() == transform_at index 0
    auto r_legacy = eng.transform(spec, "procfetch", responses);
    REQUIRE(r_legacy.ok);
    auto jl = nlohmann::json::parse(r_legacy.json);
    CHECK(jl["chart_type"] == "pie");
}

TEST_CASE("VisualizationEngine: malformed JSON → error", "[visualization][engine]") {
    VisualizationEngine eng;
    auto r = eng.transform("{not json", "processes", {});
    CHECK_FALSE(r.ok);
}

TEST_CASE("VisualizationEngine: invalid chart type → error", "[visualization][engine]") {
    VisualizationEngine eng;
    auto spec = R"({"type":"radar","processor":"single_series","labelField":0})";
    auto r = eng.transform(spec, "processes", {});
    CHECK_FALSE(r.ok);
    CHECK(r.json.find("invalid chart type") != std::string::npos);
}

TEST_CASE("VisualizationEngine: invalid processor → error", "[visualization][engine]") {
    VisualizationEngine eng;
    auto spec = R"({"type":"pie","processor":"random_walk","labelField":0})";
    auto r = eng.transform(spec, "processes", {});
    CHECK_FALSE(r.ok);
    CHECK(r.json.find("invalid processor") != std::string::npos);
}

TEST_CASE("VisualizationEngine: single_series Pie counts label occurrences",
          "[visualization][engine][pie][single_series]") {
    // procfetch schema: Agent + PID + Name + Path + SHA-1 — label_field=0
    // (after the implicit Agent column) targets PID. Use Name (col 1) so we
    // group by process name across two agents.
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a1",
        "1|chrome|/usr/bin/chrome|deadbeef\n"
        "2|firefox|/usr/bin/firefox|cafebabe\n"
        "3|chrome|/usr/bin/chrome|deadbeef"));
    responses.push_back(make_resp("a2",
        "10|chrome|/usr/bin/chrome|deadbeef\n"
        "11|sshd|/usr/sbin/sshd|baadf00d"));

    VisualizationEngine eng;
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1,"title":"Procs"})";
    auto r = eng.transform(spec, "procfetch", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    CHECK(j["chart_type"] == "pie");
    CHECK(j["title"] == "Procs");
    REQUIRE(j["labels"].is_array());
    REQUIRE(j["series"].size() == 1);

    // Pull labels+counts into a map for order-independent assertions
    auto labels = j["labels"];
    auto data = j["series"][0]["data"];
    std::map<std::string, double> counts;
    for (size_t i = 0; i < labels.size(); ++i)
        counts[labels[i].get<std::string>()] = data[i].get<double>();

    CHECK(counts["chrome"] == 3);
    CHECK(counts["firefox"] == 1);
    CHECK(counts["sshd"] == 1);

    CHECK(j["meta"]["responses_total"] == 2);
    CHECK(j["meta"]["responses_succeeded"] == 2);
}

TEST_CASE("VisualizationEngine: single_series Bar with value_field sums",
          "[visualization][engine][bar][single_series]") {
    // netstat schema: Agent + Proto + Local Addr + Local Port + Remote Addr +
    // Remote Port + State + PID. value_field=2 (Local Port) — odd but exercises
    // the numeric summation path. label_field=5 (State).
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a1",
        "tcp|0.0.0.0|80|0.0.0.0|0|LISTEN|1\n"
        "tcp|0.0.0.0|443|0.0.0.0|0|LISTEN|2\n"
        "tcp|10.0.0.1|22|10.0.0.2|55555|ESTABLISHED|3"));

    VisualizationEngine eng;
    auto spec = R"({"type":"bar","processor":"single_series","labelField":5,
                    "valueField":2,"valueLabel":"Sum of ports"})";
    auto r = eng.transform(spec, "netstat", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    CHECK(j["chart_type"] == "bar");

    std::map<std::string, double> totals;
    for (size_t i = 0; i < j["labels"].size(); ++i)
        totals[j["labels"][i].get<std::string>()] = j["series"][0]["data"][i].get<double>();
    CHECK(totals["LISTEN"] == 80 + 443);
    CHECK(totals["ESTABLISHED"] == 22);
    CHECK(j["series"][0]["name"] == "Sum of ports");
}

TEST_CASE("VisualizationEngine: max_categories caps and produces an 'Other' bucket",
          "[visualization][engine][single_series][max_categories]") {
    // Build 6 distinct labels with descending counts and cap at 3.
    std::string out;
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j <= i; ++j)
            out += "p" + std::to_string(i) + "|state" + std::to_string(i) + "\n";

    std::vector<StoredResponse> responses{make_resp("a1", out)};
    VisualizationEngine eng;
    auto spec = R"({"type":"column","processor":"single_series","labelField":1,
                    "maxCategories":3})";
    auto r = eng.transform(spec, "processes", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    REQUIRE(j["labels"].size() == 4); // 3 top + Other
    CHECK(j["labels"][3] == "Other");
    // The 3 dropped buckets had counts 1, 2, 3 → Other = 6
    auto data = j["series"][0]["data"];
    CHECK(data[3] == 6);
}

TEST_CASE("VisualizationEngine: multi_series groups by series_field",
          "[visualization][engine][multi_series][column]") {
    // Schema: Agent + Severity + Category + Title + Detail (vuln_scan, 4 fields)
    // label_field=0 (Severity), series_field=1 (Category).
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a1",
        "high|chrome|CVE-1|d1\n"
        "high|chrome|CVE-2|d2\n"
        "low|chrome|CVE-3|d3\n"
        "high|firefox|CVE-4|d4\n"
        "low|firefox|CVE-5|d5"));

    VisualizationEngine eng;
    auto spec = R"({"type":"column","processor":"multi_series","labelField":0,"seriesField":1})";
    auto r = eng.transform(spec, "vuln_scan", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    REQUIRE(j["series"].size() == 2);

    std::map<std::string, std::map<std::string, double>> got;
    auto labels = j["labels"];
    for (auto& s : j["series"]) {
        auto name = s["name"].get<std::string>();
        for (size_t i = 0; i < labels.size(); ++i)
            got[name][labels[i].get<std::string>()] = s["data"][i].get<double>();
    }
    CHECK(got["chrome"]["high"] == 2);
    CHECK(got["chrome"]["low"] == 1);
    CHECK(got["firefox"]["high"] == 1);
    CHECK(got["firefox"]["low"] == 1);
}

TEST_CASE("VisualizationEngine: datetime_series uses response timestamp by default",
          "[visualization][engine][datetime_series][line]") {
    // Default x_field (omitted) means "agent_timestamp" — one point per
    // response. y_field=null → count rows in each response. series falls back
    // to agent_id when series_field isn't set.
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a1",
        "1|chrome|/usr/bin/chrome|deadbeef\n2|firefox|/usr/bin/firefox|cafebabe",
        /*status=*/0, /*timestamp=*/1000));
    responses.push_back(make_resp("a1",
        "1|chrome|/usr/bin/chrome|deadbeef",
        0, 2000));
    responses.push_back(make_resp("a2",
        "5|sshd|/usr/sbin/sshd|baadf00d\n6|nginx|/usr/sbin/nginx|c0ffee\n7|cron|/usr/sbin/cron|0",
        0, 1500));

    VisualizationEngine eng;
    auto spec = R"({"type":"line","processor":"datetime_series","title":"events"})";
    auto r = eng.transform(spec, "procfetch", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    CHECK(j["chart_type"] == "line");
    CHECK(j["x_axis"] == "datetime");

    REQUIRE(j["x"].size() == 3); // unioned 1000, 1500, 2000
    CHECK(j["x"][0] == 1000);
    CHECK(j["x"][1] == 1500);
    CHECK(j["x"][2] == 2000);

    REQUIRE(j["series"].size() == 2);
    std::map<std::string, std::vector<double>> got;
    for (auto& s : j["series"]) {
        auto data = s["data"];
        std::vector<double> vec;
        for (auto& d : data) vec.push_back(d.get<double>());
        got[s["name"].get<std::string>()] = vec;
    }
    // a1 has 2 lines at t=1000 and 1 line at t=2000, padded with 0 at t=1500
    CHECK(got["a1"] == std::vector<double>{2, 0, 1});
    // a2 has 3 lines at t=1500, padded with 0 elsewhere
    CHECK(got["a2"] == std::vector<double>{0, 3, 0});
}

TEST_CASE("VisualizationEngine: datetime_series area shape",
          "[visualization][engine][datetime_series][area]") {
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("agent",
        "1|svc|/u/s/svc|deadbeef", 0, 100));

    VisualizationEngine eng;
    auto spec = R"({"type":"area","processor":"datetime_series"})";
    auto r = eng.transform(spec, "procfetch", responses);
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    CHECK(j["chart_type"] == "area");
    REQUIRE(j["x"].size() == 1);
    CHECK(j["x"][0] == 100);
    CHECK(j["series"][0]["data"][0] == 1);
}

TEST_CASE("VisualizationEngine: empty response set → empty labels & series",
          "[visualization][engine][edge]") {
    VisualizationEngine eng;
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1})";
    auto r = eng.transform(spec, "procfetch", {});
    REQUIRE(r.ok);

    auto j = nlohmann::json::parse(r.json);
    CHECK(j["chart_type"] == "pie");
    CHECK(j["labels"].size() == 0);
    REQUIRE(j["series"].size() == 1);
    CHECK(j["series"][0]["data"].size() == 0);
    CHECK(j["meta"]["responses_total"] == 0);
}

TEST_CASE("VisualizationEngine: status counts split between succeeded/failed",
          "[visualization][engine][meta]") {
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a1", "1|svc|/p|s", /*status=*/0));
    responses.push_back(make_resp("a2", "", /*status=*/2));
    responses.push_back(make_resp("a3", "2|svc|/p|s", /*status=*/0));

    VisualizationEngine eng;
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1})";
    auto r = eng.transform(spec, "procfetch", responses);
    REQUIRE(r.ok);
    auto j = nlohmann::json::parse(r.json);
    CHECK(j["meta"]["responses_total"] == 3);
    CHECK(j["meta"]["responses_succeeded"] == 2);
    CHECK(j["meta"]["responses_failed"] == 1);
}

TEST_CASE("VisualizationEngine: unknown plugin falls back to default 2-column schema",
          "[visualization][engine][edge]") {
    // Default schema is Agent + Output (single field). label_field=0 means
    // "the entire output line", treated as a single bucket per distinct line.
    std::vector<StoredResponse> responses;
    responses.push_back(make_resp("a", "alpha\nbeta\nalpha\nalpha"));

    VisualizationEngine eng;
    auto spec = R"({"type":"bar","processor":"single_series","labelField":0})";
    auto r = eng.transform(spec, "no_such_plugin", responses);
    REQUIRE(r.ok);
    auto j = nlohmann::json::parse(r.json);

    std::map<std::string, double> got;
    for (size_t i = 0; i < j["labels"].size(); ++i)
        got[j["labels"][i].get<std::string>()] = j["series"][0]["data"][i].get<double>();
    CHECK(got["alpha"] == 3);
    CHECK(got["beta"] == 1);
}
