%%%-------------------------------------------------------------------
%%% @doc simple_one_for_one supervisor for yuzu_gw_agent processes.
%%%
%%% Each connected agent gets one process, started dynamically when
%%% the agent's Subscribe bidi stream arrives. `temporary` restart
%%% strategy: if an agent process crashes, the agent reconnects
%%% naturally via Register → Subscribe.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_sup).
-behaviour(supervisor).

-export([start_link/0, start_agent/1, count/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start a new agent process for an incoming Subscribe stream.
-spec start_agent(map()) -> {ok, pid()} | {error, term()}.
start_agent(Args) ->
    supervisor:start_child(?SERVER, [Args]).

%% @doc Return the number of active agent processes.
-spec count() -> non_neg_integer().
count() ->
    proplists:get_value(active, supervisor:count_children(?SERVER), 0).

%%--------------------------------------------------------------------
%% supervisor callback
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy  => simple_one_for_one,
        intensity => 0,    %% Don't restart; agent will reconnect
        period    => 1
    },

    ChildSpec = #{
        id       => agent,
        start    => {yuzu_gw_agent, start_link, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },

    {ok, {SupFlags, [ChildSpec]}}.
