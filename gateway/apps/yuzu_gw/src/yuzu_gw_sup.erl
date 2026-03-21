%%%-------------------------------------------------------------------
%%% @doc Top-level supervisor for the yuzu gateway.
%%%
%%% Supervision tree (one_for_one):
%%%   1. yuzu_gw_registry          — ETS owner + pg coordinator
%%%   2. yuzu_gw_upstream          — gRPC client for register/inventory/notify
%%%   3. yuzu_gw_heartbeat_buffer  — dedicated heartbeat batching worker
%%%   4. yuzu_gw_router            — command fanout coordinator
%%%   5. yuzu_gw_agent_sup         — simple_one_for_one for agent processes
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_sup).
-behaviour(supervisor).

-export([start_link/0, start_pg/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start the pg scope, tolerating already-started.
start_pg() ->
    case pg:start_link(yuzu_gw) of
        {ok, Pid}                       -> {ok, Pid};
        {error, {already_started, Pid}} -> link(Pid), {ok, Pid};
        Error                           -> Error
    end.

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
        #{id       => pg_scope,
          start    => {yuzu_gw_sup, start_pg, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

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

        #{id       => yuzu_gw_heartbeat_buffer,
          start    => {yuzu_gw_heartbeat_buffer, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_router,
          start    => {yuzu_gw_router, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_gauge,
          start    => {yuzu_gw_gauge, start_link, []},
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
