%%%-------------------------------------------------------------------
%%% @doc Integration test for the gateway Prometheus /metrics endpoint.
%%%
%%% Verifies that prometheus_httpd serves metrics in Prometheus text
%%% format on the configured port, and that all declared gateway
%%% metrics appear in the output.
%%%
%%% Requires:
%%%   - inets, prometheus, telemetry started
%%%   - yuzu_gw_telemetry:setup() called
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_prometheus_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([all/0, suite/0,
         init_per_suite/1, end_per_suite/1]).

%% Test cases
-export([
    metrics_endpoint_responds/1,
    metrics_contain_agent_counters/1,
    metrics_contain_beam_gauges/1,
    metrics_contain_command_histograms/1,
    metrics_content_type_is_prometheus/1
]).

-define(PROM_PORT, 19568).  %% Unique test port to avoid conflicts

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [metrics_endpoint_responds,
     metrics_contain_agent_counters,
     metrics_contain_beam_gauges,
     metrics_contain_command_histograms,
     metrics_content_type_is_prometheus].

init_per_suite(Config) ->
    application:ensure_all_started(inets),
    application:ensure_all_started(prometheus),
    application:ensure_all_started(telemetry),
    %% Starting prometheus_httpd app calls prometheus_http_impl:setup/0,
    %% which declares the internal telemetry_scrape_* metrics required
    %% for the /metrics endpoint handler to work.
    application:ensure_all_started(prometheus_httpd),

    %% Set up prometheus metrics (same as app startup).
    yuzu_gw_telemetry:setup(),

    %% Start prometheus_httpd on a test port.
    application:set_env(prometheus, prometheus_http, [{port, ?PROM_PORT}, {path, "/metrics"}]),
    {ok, HttpdPid} = prometheus_httpd:start(),

    %% Increment some counters so they appear in output.
    prometheus_counter:inc(yuzu_gw_agents_connected_total, [<<"test-node">>]),
    prometheus_counter:inc(yuzu_gw_commands_dispatched_total, [<<"test-plugin">>]),

    [{prom_port, ?PROM_PORT}, {httpd_pid, HttpdPid} | Config].

end_per_suite(Config) ->
    HttpdPid = proplists:get_value(httpd_pid, Config),
    inets:stop(httpd, HttpdPid),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

metrics_endpoint_responds(Config) ->
    Port = proplists:get_value(prom_port, Config),
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/metrics",
    {ok, {{_, 200, _}, _Headers, _Body}} = httpc:request(get, {Url, []}, [], []).

metrics_contain_agent_counters(Config) ->
    Body = fetch_metrics(Config),
    ?assert(string:find(Body, "yuzu_gw_agents_connected_total") =/= nomatch),
    ?assert(string:find(Body, "yuzu_gw_agents_disconnected_total") =/= nomatch),
    ?assert(string:find(Body, "yuzu_gw_commands_dispatched_total") =/= nomatch).

metrics_contain_beam_gauges(Config) ->
    Body = fetch_metrics(Config),
    %% These are declared by yuzu_gw_telemetry:setup() even if yuzu_gw_gauge
    %% hasn't ticked yet. Prometheus still declares them in output.
    ?assert(string:find(Body, "yuzu_gw_beam_process_count") =/= nomatch
            orelse string:find(Body, "yuzu_gw_agents_current") =/= nomatch).

metrics_contain_command_histograms(Config) ->
    Body = fetch_metrics(Config),
    ?assert(string:find(Body, "yuzu_gw_command_duration_ms") =/= nomatch
            orelse string:find(Body, "yuzu_gw_upstream_rpc_duration_ms") =/= nomatch).

metrics_content_type_is_prometheus(Config) ->
    Port = proplists:get_value(prom_port, Config),
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/metrics",
    {ok, {{_, 200, _}, Headers, _Body}} = httpc:request(get, {Url, []}, [], []),
    ContentType = proplists:get_value("content-type", Headers, ""),
    ?assert(string:find(ContentType, "text/plain") =/= nomatch).

%%%===================================================================
%%% Internal
%%%===================================================================

fetch_metrics(Config) ->
    Port = proplists:get_value(prom_port, Config),
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/metrics",
    {ok, {{_, 200, _}, _, Body}} = httpc:request(get, {Url, []}, [], []),
    Body.
