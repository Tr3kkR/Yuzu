%%%-------------------------------------------------------------------
%%% @doc yuzu_gw application callback module.
%%%
%%% Starts the top-level supervisor, initialises telemetry handlers,
%%% and creates the pg scope used for cluster-wide agent groups.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app).
-behaviour(application).

-export([start/2, stop/1]).

%%--------------------------------------------------------------------
%% application callbacks
%%--------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    %% Attach telemetry/prometheus handlers.
    yuzu_gw_telemetry:setup(),

    %% Start Prometheus HTTP exporter for /metrics endpoint.
    Port = application:get_env(yuzu_gw, prometheus_port, 9568),
    application:set_env(prometheus, prometheus_http, [{port, Port}, {path, "/metrics"}]),
    {ok, _} = prometheus_httpd:start(),
    logger:info("Prometheus metrics endpoint started on port ~p", [Port]),

    %% Start the supervision tree.
    yuzu_gw_sup:start_link().

stop(_State) ->
    ok.
