%%%-------------------------------------------------------------------
%%% @doc Agent routing registry — ETS + pg.
%%%
%%% ETS (`yuzu_gw_agents`): fast O(1) lookup by agent_id.
%%% ETS (`yuzu_gw_pending`): pending Register→Subscribe state with TTL.
%%% pg (`yuzu_gw` scope):   cluster-aware process groups for broadcast
%%%   and plugin-targeted fanout.
%%%
%%% This gen_server owns the ETS tables and coordinates pg group
%%% membership on behalf of agent processes.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry).
-behaviour(gen_server).

%% API
-export([start_link/0,
         register_agent/5,
         deregister_agent/1,
         lookup/1,
         all_agents/0,
         all_agent_pids/0,
         agents_for_plugin/1,
         agent_count/0,
         list_agents/2,
         store_pending/2,
         take_pending/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).
-define(TABLE,  yuzu_gw_agents).
-define(PENDING_TABLE, yuzu_gw_pending).
-define(PG_SCOPE, yuzu_gw).
-define(PENDING_TTL_MS, 120000).     %% 2 minutes
-define(PENDING_SWEEP_MS, 60000).    %% 1 minute

-record(state, {
    monitor_refs :: #{reference() => binary()},
    sweep_timer  :: reference()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Register an agent process in the routing table.
%% Called by yuzu_gw_agent:init/1 from the agent process itself.
-spec register_agent(binary(), pid(), binary() | undefined, [binary()], binary()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname) ->
    gen_server:call(?SERVER, {register, AgentId, Pid, SessionId, Plugins, Hostname}).

%% @doc Remove an agent from the routing table.
-spec deregister_agent(binary()) -> ok.
deregister_agent(AgentId) ->
    gen_server:cast(?SERVER, {deregister, AgentId}).

%% @doc Lookup an agent by ID. Returns {ok, Pid} or error.
-spec lookup(binary()) -> {ok, pid()} | error.
lookup(AgentId) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, _, _, _}] ->
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
    [AgentId || {AgentId, _, _, _, _, _, _} <- ets:tab2list(?TABLE)].

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
        _         -> lists:dropwhile(fun({Id, _, _, _, _, _, _}) -> Id =< Cursor end, All)
    end,
    Page = lists:sublist(Filtered, Limit),
    Agents = [#{agent_id     => Id,
                pid          => Pid,
                node         => Node,
                session_id   => Sid,
                plugins      => Plugins,
                connected_at => T,
                hostname     => Hn}
              || {Id, Pid, Node, Sid, Plugins, T, Hn} <- Page],
    NextCursor = case length(Page) =:= Limit andalso length(Filtered) > Limit of
        true  -> element(1, lists:last(Page));
        false -> undefined
    end,
    {Agents, NextCursor}.

%% @doc Store pending registration info for a session.
%% Called by agent_service on Register, consumed by Subscribe.
-spec store_pending(binary(), map()) -> ok.
store_pending(SessionId, Info) ->
    ets:insert(?PENDING_TABLE, {SessionId, Info, erlang:system_time(millisecond)}),
    ok.

%% @doc Atomically retrieve and delete pending registration info.
%% Returns the info map or undefined if not found / expired.
-spec take_pending(binary()) -> map() | undefined.
take_pending(SessionId) ->
    case ets:lookup(?PENDING_TABLE, SessionId) of
        [{_, Info, _}] ->
            ets:delete(?PENDING_TABLE, SessionId),
            Info;
        [] ->
            undefined
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?TABLE, [named_table, set, public, {read_concurrency, true}]),
    ets:new(?PENDING_TABLE, [named_table, set, public]),
    TRef = erlang:send_after(?PENDING_SWEEP_MS, self(), sweep_pending),
    {ok, #state{monitor_refs = #{}, sweep_timer = TRef}}.

handle_call({register, AgentId, Pid, SessionId, Plugins, Hostname}, _From,
            #state{monitor_refs = Mons} = State) ->
    %% Remove any stale entry for this agent_id (returns cleaned Mons).
    Mons1 = maybe_cleanup(AgentId, Mons),

    %% Insert into ETS.
    Now = erlang:system_time(millisecond),
    ets:insert(?TABLE, {AgentId, Pid, node(Pid), SessionId, Plugins, Now, Hostname}),

    %% Join pg groups.
    pg:join(?PG_SCOPE, all_agents, Pid),
    lists:foreach(fun(Plugin) ->
        pg:join(?PG_SCOPE, {plugin, Plugin}, Pid)
    end, Plugins),

    %% Monitor the agent process for automatic cleanup.
    MonRef = monitor(process, Pid),
    Mons2 = Mons1#{MonRef => AgentId},

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

handle_info(sweep_pending, State) ->
    Now = erlang:system_time(millisecond),
    Expired = ets:foldl(fun({SessionId, _, StoredAt}, Acc) ->
        case Now - StoredAt > ?PENDING_TTL_MS of
            true  -> [SessionId | Acc];
            false -> Acc
        end
    end, [], ?PENDING_TABLE),
    lists:foreach(fun(Id) -> ets:delete(?PENDING_TABLE, Id) end, Expired),
    case length(Expired) of
        0 -> ok;
        N -> logger:info("Swept ~b expired pending registrations", [N])
    end,
    TRef = erlang:send_after(?PENDING_SWEEP_MS, self(), sweep_pending),
    {noreply, State#state{sweep_timer = TRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

do_deregister(AgentId, #state{monitor_refs = Mons} = State) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, Plugins, _, _}] ->
            ets:delete(?TABLE, AgentId),
            %% pg auto-removes on process exit, but leave explicitly for clarity.
            catch pg:leave(?PG_SCOPE, all_agents, Pid),
            lists:foreach(fun(Plugin) ->
                catch pg:leave(?PG_SCOPE, {plugin, Plugin}, Pid)
            end, Plugins),
            %% Find and remove the monitor ref.
            Mons2 = maps:filter(fun(_Ref, Id) -> Id =/= AgentId end, Mons),
            {noreply, State#state{monitor_refs = Mons2}};
        [] ->
            {noreply, State}
    end.

%% @doc Clean up a stale agent entry and return the updated monitor map.
maybe_cleanup(AgentId, Mons) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, OldPid, _, _, OldPlugins, _, _}] ->
            catch pg:leave(?PG_SCOPE, all_agents, OldPid),
            lists:foreach(fun(Plugin) ->
                catch pg:leave(?PG_SCOPE, {plugin, Plugin}, OldPid)
            end, OldPlugins),
            ets:delete(?TABLE, AgentId),
            %% Demonitor old refs and remove them from the map.
            maps:fold(fun(Ref, Id, AccMons) ->
                case Id of
                    AgentId ->
                        demonitor(Ref, [flush]),
                        maps:remove(Ref, AccMons);
                    _ ->
                        AccMons
                end
            end, Mons, Mons);
        [] ->
            Mons
    end.
