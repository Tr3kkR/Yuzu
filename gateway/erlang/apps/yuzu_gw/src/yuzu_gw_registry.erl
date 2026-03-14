%%%-------------------------------------------------------------------
%%% @doc Agent routing registry — ETS + pg.
%%%
%%% ETS (`yuzu_gw_agents`): fast O(1) lookup by agent_id.
%%% pg (`yuzu_gw` scope):   cluster-aware process groups for broadcast
%%%   and plugin-targeted fanout.
%%%
%%% This gen_server owns the ETS table and coordinates pg group
%%% membership on behalf of agent processes.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry).
-behaviour(gen_server).

%% API
-export([start_link/0,
         register_agent/4,
         deregister_agent/1,
         lookup/1,
         all_agents/0,
         all_agent_pids/0,
         agents_for_plugin/1,
         agent_count/0,
         list_agents/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).
-define(TABLE,  yuzu_gw_agents).
-define(PG_SCOPE, yuzu_gw).

-record(state, {
    monitor_refs :: #{reference() => binary()}  %% MonRef => AgentId
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Register an agent process in the routing table.
%% Called by yuzu_gw_agent:init/1 from the agent process itself.
-spec register_agent(binary(), pid(), binary() | undefined, [binary()]) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins) ->
    gen_server:call(?SERVER, {register, AgentId, Pid, SessionId, Plugins}).

%% @doc Remove an agent from the routing table.
-spec deregister_agent(binary()) -> ok.
deregister_agent(AgentId) ->
    gen_server:cast(?SERVER, {deregister, AgentId}).

%% @doc Lookup an agent by ID. Returns {ok, Pid} or error.
-spec lookup(binary()) -> {ok, pid()} | error.
lookup(AgentId) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, _, _}] ->
            case is_process_alive(Pid) of
                true  -> {ok, Pid};
                false -> error
            end;
        [] ->
            error
    end.

%% @doc Return all agent IDs.
-spec all_agents() -> [binary()].
all_agents() ->
    [AgentId || {AgentId, _, _, _, _, _} <- ets:tab2list(?TABLE)].

%% @doc Return all agent pids (for broadcast via pg fallback).
-spec all_agent_pids() -> [pid()].
all_agent_pids() ->
    pg:get_members(?PG_SCOPE, all_agents).

%% @doc Return pids of agents that have a specific plugin loaded.
-spec agents_for_plugin(binary()) -> [pid()].
agents_for_plugin(PluginName) ->
    pg:get_members(?PG_SCOPE, {plugin, PluginName}).

%% @doc Total number of connected agents on this node.
-spec agent_count() -> non_neg_integer().
agent_count() ->
    ets:info(?TABLE, size).

%% @doc Paginated agent listing for dashboard queries.
%% Returns {Agents, NextCursor} where Agents is a list of maps.
-spec list_agents(non_neg_integer(), binary() | undefined) ->
    {[map()], binary() | undefined}.
list_agents(Limit, Cursor) ->
    %% Simple cursor: the last agent_id seen (lexicographic order).
    All = lists:sort(ets:tab2list(?TABLE)),
    Filtered = case Cursor of
        undefined -> All;
        <<>>      -> All;
        _         -> lists:dropwhile(fun({Id, _, _, _, _, _}) -> Id =< Cursor end, All)
    end,
    Page = lists:sublist(Filtered, Limit),
    Agents = [#{agent_id     => Id,
                pid          => Pid,
                node         => Node,
                session_id   => Sid,
                plugins      => Plugins,
                connected_at => T}
              || {Id, Pid, Node, Sid, Plugins, T} <- Page],
    NextCursor = case length(Page) =:= Limit andalso length(Filtered) > Limit of
        true  -> element(1, lists:last(Page));
        false -> undefined
    end,
    {Agents, NextCursor}.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?TABLE, [named_table, set, public, {read_concurrency, true}]),
    {ok, #state{monitor_refs = #{}}}.

handle_call({register, AgentId, Pid, SessionId, Plugins}, _From,
            #state{monitor_refs = Mons} = State) ->
    %% Remove any stale entry for this agent_id.
    maybe_cleanup(AgentId, Mons),

    %% Insert into ETS.
    Now = erlang:system_time(millisecond),
    ets:insert(?TABLE, {AgentId, Pid, node(Pid), SessionId, Plugins, Now}),

    %% Join pg groups.
    pg:join(?PG_SCOPE, all_agents, Pid),
    lists:foreach(fun(Plugin) ->
        pg:join(?PG_SCOPE, {plugin, Plugin}, Pid)
    end, Plugins),

    %% Monitor the agent process for automatic cleanup.
    MonRef = monitor(process, Pid),
    Mons2 = Mons#{MonRef => AgentId},

    {reply, ok, State#state{monitor_refs = Mons2}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({deregister, AgentId}, State) ->
    do_deregister(AgentId, State);

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MonRef, process, _Pid, _Reason},
            #state{monitor_refs = Mons} = State) ->
    case maps:find(MonRef, Mons) of
        {ok, AgentId} ->
            ets:delete(?TABLE, AgentId),
            %% pg auto-removes dead processes, but we clean ETS explicitly.
            {noreply, State#state{monitor_refs = maps:remove(MonRef, Mons)}};
        error ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

do_deregister(AgentId, #state{monitor_refs = Mons} = State) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, _, _}] ->
            ets:delete(?TABLE, AgentId),
            %% pg auto-removes on process exit, but leave explicitly for clarity.
            catch pg:leave(?PG_SCOPE, all_agents, Pid),
            %% Find and remove the monitor ref.
            Mons2 = maps:filter(fun(_Ref, Id) -> Id =/= AgentId end, Mons),
            {noreply, State#state{monitor_refs = Mons2}};
        [] ->
            {noreply, State}
    end.

maybe_cleanup(AgentId, Mons) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, OldPid, _, _, _, _}] ->
            catch pg:leave(?PG_SCOPE, all_agents, OldPid),
            ets:delete(?TABLE, AgentId),
            %% Demonitor old process.
            maps:foreach(fun(Ref, Id) ->
                case Id of
                    AgentId -> demonitor(Ref, [flush]);
                    _       -> ok
                end
            end, Mons);
        [] ->
            ok
    end.
