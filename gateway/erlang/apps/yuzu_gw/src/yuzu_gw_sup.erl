%%%-------------------------------------------------------------------
%%% @doc Top-level supervisor for the yuzu gateway.
%%%
%%% Supervision tree (one_for_one):
%%%   1. yuzu_gw_registry   — ETS owner + pg coordinator
%%%   2. yuzu_gw_upstream   — gRPC client pool to C++ server
%%%   3. yuzu_gw_router     — command fanout coordinator
%%%   4. yuzu_gw_agent_sup  — simple_one_for_one for agent processes
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% supervisor callback
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy  => one_for_one,
        intensity => 10,
        period    => 60
    },

    Children = [
        #{id       => yuzu_gw_registry,
          start    => {yuzu_gw_registry, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_upstream,
          start    => {yuzu_gw_upstream, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_router,
          start    => {yuzu_gw_router, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_agent_sup,
          start    => {yuzu_gw_agent_sup, start_link, []},
          restart  => permanent,
          shutdown => infinity,
          type     => supervisor}
    ],

    {ok, {SupFlags, Children}}.
