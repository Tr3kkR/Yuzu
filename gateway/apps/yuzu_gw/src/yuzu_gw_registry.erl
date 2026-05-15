%%%-------------------------------------------------------------------
%%% @doc Agent routing registry — ETS + pg.
%%%
%%% ETS (`yuzu_gw_agents`): fast O(1) lookup by agent_id. Each row also
%%%   carries the verbatim `RegisterRequest` the agent first sent, so
%%%   `yuzu_gw_upstream` can re-proxy it byte-for-byte when the upstream
%%%   connection re-establishes (the server comes back with an empty
%%%   registry and must relearn every agent the gateway already holds).
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
         register_agent/6,
         deregister_agent/1,
         lookup/1,
         all_agents/0,
         all_agent_pids/0,
         all_register_reqs/0,
         agents_for_plugin/1,
         agent_count/0,
         list_agents/2,
         store_pending/2,
         take_pending/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

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

%% @doc Register an agent with no stashed RegisterRequest.
%%
%% Back-compat entry point: production registration goes through
%% register_agent/6 (yuzu_gw_agent:init/1 always has the verbatim
%% request). This /5 form is for callers — chiefly routing-focused
%% tests — that do not exercise the upstream-reconnect replay path; it
%% records an empty request, so such an agent is simply skipped by the
%% replay drip.
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname) ->
    register_agent(AgentId, Pid, SessionId, Plugins, Hostname, #{}).

%% @doc Register an agent process in the routing table.
%% Called by yuzu_gw_agent:init/1 from the agent process itself.
%%
%% RegisterReq is the verbatim `yuzu.agent.v1.RegisterRequest' map the
%% agent originally sent; it is stashed so the upstream client can
%% re-proxy it on reconnect (see all_register_reqs/0).
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary(), map()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq) ->
    gen_server:call(?SERVER,
                    {register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq},
                    30000).

%% @doc Remove an agent from the routing table.
-spec deregister_agent(binary()) -> ok.
deregister_agent(AgentId) ->
    gen_server:cast(?SERVER, {deregister, AgentId}).

%% @doc Lookup an agent by ID. Returns {ok, Pid} or error.
-spec lookup(binary()) -> {ok, pid()} | error.
lookup(AgentId) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, _, _, _, _}] ->
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
    [AgentId || {AgentId, _, _, _, _, _, _, _} <- ets:tab2list(?TABLE)].

%% @doc Return all agent pids (for broadcast via pg fallback).
-spec all_agent_pids() -> [pid()].
all_agent_pids() ->
    pg:get_members(?PG_SCOPE, all_agents).

%% @doc Return {AgentId, RegisterRequest} for every currently-registered
%% agent. Used by yuzu_gw_upstream to re-proxy registrations when the
%% upstream connection re-establishes. Because this reads straight from
%% ETS at call time, an agent that deregistered during the outage is
%% already absent — it will not be replayed.
%%
%% Returns [] if the table does not exist (registry not started, or
%% torn down) — same defensive contract as agent_count/0, so a caller
%% on the reconnect path never crashes just because the registry is
%% momentarily absent.
-spec all_register_reqs() -> [{binary(), map()}].
all_register_reqs() ->
    case ets:info(?TABLE, size) of
        undefined ->
            [];
        _ ->
            [{AgentId, RegisterReq}
             || {AgentId, _, _, _, _, _, _, RegisterReq} <- ets:tab2list(?TABLE)]
    end.

%% @doc Return pids of agents that have a specific plugin loaded.
-spec agents_for_plugin(binary()) -> [pid()].
agents_for_plugin(PluginName) ->
    pg:get_members(?PG_SCOPE, {plugin, PluginName}).

%% @doc Total number of connected agents on this node.
-spec agent_count() -> non_neg_integer().
agent_count() ->
    case ets:info(?TABLE, size) of
        undefined -> 0;
        N -> N
    end.

%% @doc Paginated agent listing for dashboard queries.
%% Returns {Agents, NextCursor} where Agents is a list of maps.
%%
%% Uses ets:select/2 with a match spec for cursor-based pagination.
%% This is O(k) where k = page size, instead of O(n log n) from the
%% previous tab2list + sort approach.
-spec list_agents(non_neg_integer(), binary() | undefined) ->
    {[map()], binary() | undefined}.
list_agents(Limit, Cursor) ->
    %% Build a match spec that selects rows where agent_id > Cursor.
    %% ETS ordered_set would give us ordered traversal natively, but
    %% the table is a `set` — so we use a guard condition on the key
    %% and fetch Limit+1 to detect whether more pages exist.
    %%
    %% '$8' (the verbatim RegisterRequest) is matched but deliberately
    %% not projected — it is an internal replay artifact, not dashboard
    %% data — so we select only the seven display fields explicitly.
    MatchHead = {'$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8'},
    Guard = case Cursor of
        undefined -> [];
        <<>>      -> [];
        _         -> [{'>', '$1', {const, Cursor}}]
    end,
    Result = [{{'$1', '$2', '$3', '$4', '$5', '$6', '$7'}}],
    MatchSpec = [{MatchHead, Guard, Result}],

    %% Select all matching rows, then sort only this subset and take Limit+1.
    %% For small page sizes this is vastly cheaper than sorting the full table.
    Selected = ets:select(?TABLE, MatchSpec),
    Sorted = lists:sort(Selected),
    PagePlusOne = lists:sublist(Sorted, Limit + 1),

    {Page, HasMore} = case length(PagePlusOne) > Limit of
        true  -> {lists:sublist(PagePlusOne, Limit), true};
        false -> {PagePlusOne, false}
    end,

    Agents = [#{agent_id     => Id,
                pid          => Pid,
                node         => Node,
                session_id   => Sid,
                plugins      => Plugins,
                connected_at => T,
                hostname     => Hn}
              || {Id, Pid, Node, Sid, Plugins, T, Hn} <- Page],

    NextCursor = case HasMore andalso Page =/= [] of
        true  ->
            LastRow = lists:last(Page),
            element(1, LastRow);  %% agent_id is the first tuple element
        false ->
            undefined
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

handle_call({register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq}, _From,
            #state{monitor_refs = Mons} = State) ->
    %% Remove any stale entry for this agent_id (returns cleaned Mons).
    Mons1 = maybe_cleanup(AgentId, Mons),

    %% Insert into ETS. The trailing field is the verbatim RegisterRequest,
    %% kept so yuzu_gw_upstream can re-proxy it on upstream reconnect.
    Now = erlang:system_time(millisecond),
    ets:insert(?TABLE, {AgentId, Pid, node(Pid), SessionId, Plugins, Now,
                        Hostname, RegisterReq}),

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

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

do_deregister(AgentId, #state{monitor_refs = Mons} = State) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, Plugins, _, _, _}] ->
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
        [{_, OldPid, _, _, OldPlugins, _, _, _}] ->
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
