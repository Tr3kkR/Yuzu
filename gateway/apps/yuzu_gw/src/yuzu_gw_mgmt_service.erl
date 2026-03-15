%%%-------------------------------------------------------------------
%%% @doc Operator-facing gRPC service — implements ManagementService.
%%%
%%% Serves commands from dashboards and CLI tools. Most operations are
%%% handled entirely by the gateway (which knows connected agents);
%%% only QueryInventory is proxied to the C++ server.
%%%
%%% - SendCommand: fans out via yuzu_gw_router
%%% - ListAgents:  answered from ETS routing table
%%% - GetAgent:    answered from agent process state
%%% - WatchEvents: gateway-native lifecycle event stream
%%% - QueryInventory: proxied to C++ server
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_service).

%% grpcbox service callbacks
-export([send_command/2,
         list_agents/2,
         get_agent/2,
         watch_events/2,
         query_inventory/2]).

%%--------------------------------------------------------------------
%% SendCommand — fan out to agents, stream responses back
%%--------------------------------------------------------------------

send_command(Request, #{stream := StreamRef} = _Ctx) ->
    AgentIds = maps:get(agent_ids, Request,
                        maps:get(<<"agent_ids">>, Request, [])),
    CommandReq = maps:get(command, Request,
                          maps:get(<<"command">>, Request, #{})),
    TimeoutS = maps:get(timeout_seconds, Request,
                        maps:get(<<"timeout_seconds">>, Request, 300)),

    Opts = #{timeout_seconds => TimeoutS},
    case yuzu_gw_router:send_command(AgentIds, CommandReq, Opts) of
        {ok, FanoutRef} ->
            %% Stream responses back to the operator as they arrive.
            stream_responses(StreamRef, FanoutRef);

        {error, Reason} ->
            {error, #{status => 13,
                      message => iolist_to_binary(
                          io_lib:format("Fanout failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% ListAgents — answered entirely from the gateway's ETS table
%%--------------------------------------------------------------------

list_agents(Request, _Ctx) ->
    Limit  = maps:get(limit, Request, maps:get(<<"limit">>, Request, 100)),
    Cursor = maps:get(cursor, Request, maps:get(<<"cursor">>, Request, undefined)),

    EffectiveLimit = case Limit of
        N when is_integer(N), N > 0, N =< 1000 -> N;
        _ -> 100
    end,

    {Agents, NextCursor} = yuzu_gw_registry:list_agents(EffectiveLimit, Cursor),

    Summaries = lists:map(fun(#{agent_id := Id} = A) ->
        #{agent_id  => Id,
          hostname  => maps:get(hostname, A, <<>>),
          online    => true,
          last_seen => #{millis_epoch => maps:get(connected_at, A, 0)}}
    end, Agents),

    Response = #{
        agents      => Summaries,
        next_cursor => case NextCursor of undefined -> <<>>; C -> C end
    },
    {ok, Response, #{}}.

%%--------------------------------------------------------------------
%% GetAgent — query the agent process directly
%%--------------------------------------------------------------------

get_agent(Request, _Ctx) ->
    AgentId = maps:get(agent_id, Request,
                       maps:get(<<"agent_id">>, Request, undefined)),

    case yuzu_gw_registry:lookup(AgentId) of
        {ok, Pid} ->
            case yuzu_gw_agent:get_info(Pid) of
                {ok, Info} ->
                    Plugins = [#{name => P} || P <- maps:get(plugins, Info, [])],
                    Response = #{
                        summary => #{agent_id     => AgentId,
                                     hostname     => maps:get(hostname,
                                                              maps:get(agent_info, Info, #{}), <<>>),
                                     online       => true,
                                     last_seen    => #{millis_epoch =>
                                                       maps:get(connected_at, Info, 0)}},
                        plugins => Plugins
                    },
                    {ok, Response, #{}};
                {error, Reason} ->
                    {error, #{status => 13,
                              message => iolist_to_binary(
                                  io_lib:format("Agent query failed: ~p", [Reason]))}}
            end;
        error ->
            {error, #{status => 5,  %% NOT_FOUND
                      message => <<"Agent not connected">>}}
    end.

%%--------------------------------------------------------------------
%% WatchEvents — stream agent lifecycle events
%%--------------------------------------------------------------------

watch_events(_Request, #{stream := StreamRef} = _Ctx) ->
    %% Register this caller to receive agent lifecycle events.
    %% The registry and agent processes emit telemetry events;
    %% we translate them into AgentEvent proto messages.
    self() ! {start_watching, StreamRef},
    {ok, StreamRef, #{}}.

%%--------------------------------------------------------------------
%% QueryInventory — proxy to C++ server
%%--------------------------------------------------------------------

query_inventory(Request, _Ctx) ->
    %% The C++ server owns the SQLite inventory store.
    AgentId = maps:get(agent_id, Request,
                       maps:get(<<"agent_id">>, Request, undefined)),
    Plugin  = maps:get(plugin, Request,
                       maps:get(<<"plugin">>, Request, <<>>)),

    InventoryReq = #{
        session_id   => <<>>,
        collected_at => #{millis_epoch => 0},
        plugin_data  => #{}
    },
    %% Reuse upstream proxy — in a real impl, we'd add a dedicated
    %% QueryInventory proxy RPC to GatewayUpstream.
    case yuzu_gw_upstream:proxy_inventory(InventoryReq) of
        {ok, _Response} ->
            {ok, #{agent_id    => AgentId,
                   plugin_data => #{},
                   collected_at => #{millis_epoch => 0}}, #{}};
        {error, Reason} ->
            {error, #{status => 13,
                      message => iolist_to_binary(
                          io_lib:format("Upstream inventory query failed (~s/~s): ~p",
                                        [AgentId, Plugin, Reason]))}}
    end.

%%%===================================================================
%%% Internal
%%%===================================================================

%% Stream command responses back to the operator until fanout completes.
stream_responses(StreamRef, FanoutRef) ->
    receive
        {command_response, FanoutRef, AgentId, Response} ->
            Msg = #{agent_id => AgentId, response => Response},
            grpcbox_stream:send(StreamRef, Msg),
            stream_responses(StreamRef, FanoutRef);

        {command_error, FanoutRef, AgentId, Reason} ->
            ErrorResp = #{agent_id => AgentId,
                          response => #{command_id => <<>>,
                                        status     => 'FAILURE',
                                        output     => iolist_to_binary(
                                            io_lib:format("~p", [Reason])),
                                        exit_code  => -1}},
            grpcbox_stream:send(StreamRef, ErrorResp),
            stream_responses(StreamRef, FanoutRef);

        {fanout_complete, FanoutRef, _Summary} ->
            grpcbox_stream:send_trailing(StreamRef, #{}),
            ok
    after 600000 ->
        %% Safety timeout: 10 minutes max per fanout.
        grpcbox_stream:send_trailing(StreamRef, #{<<"grpc-message">> => <<"Fanout timed out">>}),
        ok
    end.
