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
    %% Create the pg scope before anything tries to join groups.
    pg:start_link(yuzu_gw),

    %% Attach telemetry/prometheus handlers.
    yuzu_gw_telemetry:setup(),

    %% Start the supervision tree.
    yuzu_gw_sup:start_link().

stop(_State) ->
    ok.
