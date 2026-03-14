%%%-------------------------------------------------------------------
%%% @doc Agent-facing gRPC service — implements AgentService.
%%%
%%% Agents connect here using the exact same proto they already use.
%%% Zero agent-side changes required.
%%%
%%% - Register: proxied upstream to C++ server
%%% - Subscribe: terminated locally, one yuzu_gw_agent process spawned
%%% - Heartbeat: buffered for batch upstream delivery
%%% - ReportInventory: proxied upstream
%%% - ExecuteCommand: not used (Subscribe is the primary channel)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_service).

%% grpcbox service callbacks
-export([register/2,
         subscribe/2,
         heartbeat/2,
         execute_command/2,
         report_inventory/2]).

%%--------------------------------------------------------------------
%% Register — proxy to C++ server
%%--------------------------------------------------------------------

register(RegisterReq, #{headers := Headers} = _Ctx) ->
    PeerAddr = maps:get(<<"x-forwarded-for">>, Headers,
                        maps:get(<<":authority">>, Headers, <<"unknown">>)),

    case yuzu_gw_upstream:proxy_register(RegisterReq) of
        {ok, Response} ->
            %% Stash the session_id and agent_info; the agent process is
            %% created when Subscribe arrives (matched by session_id).
            SessionId = maps:get(session_id, Response,
                                 maps:get(<<"session_id">>, Response, undefined)),
            AgentInfo = maps:get(info, RegisterReq,
                                 maps:get(<<"info">>, RegisterReq, #{})),
            AgentId = extract_agent_id(AgentInfo),

            %% Store pending registration for Subscribe matching.
            persistent_term:put({yuzu_gw_pending, SessionId},
                                #{agent_id  => AgentId,
                                  agent_info => AgentInfo,
                                  peer_addr  => PeerAddr,
                                  registered_at => erlang:system_time(millisecond)}),

            logger:info("Agent ~s registered (session=~s), awaiting Subscribe",
                        [AgentId, SessionId]),
            {ok, Response, #{}};

        {error, Reason} ->
            logger:warning("Upstream Register failed: ~p", [Reason]),
            {error, #{status => 13,  %% INTERNAL
                      message => iolist_to_binary(
                          io_lib:format("Upstream registration failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Subscribe — terminate bidi stream locally
%%--------------------------------------------------------------------

subscribe(StreamRef, #{headers := Headers} = _Ctx) ->
    SessionId = maps:get(<<"x-yuzu-session-id">>, Headers, undefined),

    case SessionId of
        undefined ->
            {error, #{status => 3,  %% INVALID_ARGUMENT
                      message => <<"Missing x-yuzu-session-id header">>}};
        _ ->
            case persistent_term:get({yuzu_gw_pending, SessionId}, undefined) of
                undefined ->
                    {error, #{status => 5,  %% NOT_FOUND
                              message => <<"No pending registration for session">>}};

                #{agent_id := AgentId, agent_info := AgentInfo,
                  peer_addr := PeerAddr} ->
                    %% Clean up the pending entry.
                    persistent_term:erase({yuzu_gw_pending, SessionId}),

                    %% Spawn the agent process — it owns this stream.
                    Args = #{agent_id   => AgentId,
                             session_id => SessionId,
                             stream_ref => StreamRef,
                             agent_info => AgentInfo,
                             peer_addr  => PeerAddr},

                    case yuzu_gw_agent_sup:start_agent(Args) of
                        {ok, _Pid} ->
                            %% The agent process will read from / write to
                            %% the stream via its mailbox. grpcbox routes
                            %% incoming frames as messages to the owning process.
                            {ok, StreamRef, #{}};

                        {error, Reason} ->
                            logger:error("Failed to start agent process for ~s: ~p",
                                         [AgentId, Reason]),
                            {error, #{status => 13,
                                      message => <<"Internal: agent process start failed">>}}
                    end
            end
    end.

%%--------------------------------------------------------------------
%% Heartbeat — buffer for batch upstream delivery
%%--------------------------------------------------------------------

heartbeat(HeartbeatReq, _Ctx) ->
    yuzu_gw_upstream:queue_heartbeat(HeartbeatReq),

    %% Respond immediately — the agent doesn't need to wait for upstream ack.
    Response = #{
        acknowledged => true,
        server_time  => #{millis_epoch => erlang:system_time(millisecond)},
        pending_commands => []
    },
    {ok, Response, #{}}.

%%--------------------------------------------------------------------
%% ExecuteCommand — not used (Subscribe is the primary channel)
%%--------------------------------------------------------------------

execute_command(_CommandReq, _Ctx) ->
    {error, #{status => 12,  %% UNIMPLEMENTED
              message => <<"Use Subscribe for command delivery">>}}.

%%--------------------------------------------------------------------
%% ReportInventory — proxy upstream
%%--------------------------------------------------------------------

report_inventory(InventoryReport, _Ctx) ->
    case yuzu_gw_upstream:proxy_inventory(InventoryReport) of
        {ok, Response} ->
            {ok, Response, #{}};
        {error, Reason} ->
            logger:warning("Upstream ReportInventory failed: ~p", [Reason]),
            {error, #{status => 13,
                      message => iolist_to_binary(
                          io_lib:format("Upstream inventory report failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

extract_agent_id(AgentInfo) ->
    maps:get(<<"agent_id">>, AgentInfo,
             maps:get(agent_id, AgentInfo, <<"unknown">>)).
