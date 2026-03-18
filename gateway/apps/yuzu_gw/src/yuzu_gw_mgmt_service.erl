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

-export([json_escape/1]).

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

list_agents(Request, Ctx) ->
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
    {ok, Response, Ctx}.

%%--------------------------------------------------------------------
%% GetAgent — query the agent process directly
%%--------------------------------------------------------------------

get_agent(Request, Ctx) ->
    AgentId = maps:get(agent_id, Request,
                       maps:get(<<"agent_id">>, Request, undefined)),

    case yuzu_gw_registry:lookup(AgentId) of
        {ok, Pid} ->
            case yuzu_gw_agent:get_info(Pid) of
                {ok, Info} ->
                    Plugins = [#{name => P} || P <- maps:get(plugins, Info, [])],
                    Response = #{
                        summary => #{agent_id     => AgentId,
                                     hostname     => maps:get(hostname, Info, <<>>),
                                     online       => true,
                                     last_seen    => #{millis_epoch =>
                                                       maps:get(connected_at, Info, 0)}},
                        plugins => Plugins
                    },
                    {ok, Response, Ctx};
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

watch_events(Request, #{stream := StreamRef} = _Ctx) ->
    FilterIds = maps:get(agent_ids, Request,
                         maps:get(<<"agent_ids">>, Request, [])),
    %% Join the watcher group so agent processes can find us.
    pg:join(yuzu_gw, event_watchers, self()),
    watch_event_loop(StreamRef, FilterIds).

%%--------------------------------------------------------------------
%% QueryInventory — return agents connected to this gateway instance
%%--------------------------------------------------------------------

query_inventory(Request, Ctx) ->
    ReqAgentId = maps:get(agent_id, Request,
                           maps:get(<<"agent_id">>, Request, <<>>)),
    Plugin     = maps:get(plugin, Request,
                           maps:get(<<"plugin">>, Request, <<>>)),

    %% Fetch all connected agents from this gateway's ETS table.
    {AllAgents, _} = yuzu_gw_registry:list_agents(10000, undefined),

    %% Filter by agent_id if specified.
    Agents1 = case ReqAgentId of
        <<>> -> AllAgents;
        _    -> [A || A <- AllAgents, maps:get(agent_id, A) =:= ReqAgentId]
    end,

    %% Filter by plugin if specified.
    Agents2 = case Plugin of
        <<>> -> Agents1;
        _    -> [A || A <- Agents1, lists:member(Plugin, maps:get(plugins, A, []))]
    end,

    %% Build plugin_data: agent_id => JSON-encoded agent summary (as bytes).
    PluginData = maps:from_list([
        {maps:get(agent_id, A), agent_to_json(A)}
        || A <- Agents2
    ]),

    Now = erlang:system_time(millisecond),
    {ok, #{agent_id     => ReqAgentId,
           plugin_data  => PluginData,
           collected_at => #{millis_epoch => Now}}, Ctx}.

%%%===================================================================
%%% Internal
%%%===================================================================

%% Loop receiving agent lifecycle events and streaming them to the operator.
%% FilterIds = [] means all agents; otherwise only matching agent_ids are sent.
watch_event_loop(StreamRef, FilterIds) ->
    receive
        {agent_event, #{agent_id := AgentId} = Event} ->
            ShouldSend = case FilterIds of
                []  -> true;
                Ids -> lists:member(AgentId, Ids)
            end,
            case ShouldSend of
                true  -> grpcbox_stream:send(StreamRef, Event);
                false -> ok
            end,
            watch_event_loop(StreamRef, FilterIds);
        stop_watching ->
            pg:leave(yuzu_gw, event_watchers, self()),
            grpcbox_stream:send_trailing(StreamRef, #{})
    after 86400000 ->
        %% 24-hour safety timeout.
        pg:leave(yuzu_gw, event_watchers, self()),
        grpcbox_stream:send_trailing(StreamRef, #{})
    end.

%% Encode an agent summary (from the ETS-derived map) as a JSON binary.
agent_to_json(Agent) ->
    AgentId   = json_escape(maps:get(agent_id, Agent, <<>>)),
    SessionId = json_escape(maps:get(session_id, Agent, <<>>)),
    Node      = json_escape(atom_to_binary(maps:get(node, Agent, node()), utf8)),
    ConnAt    = maps:get(connected_at, Agent, 0),
    Plugins   = maps:get(plugins, Agent, []),
    PluginsJson = iolist_to_binary(
        [<<"[">>,
         lists:join(<<",">>, [<<$", (json_escape(P))/binary, $">> || P <- Plugins]),
         <<"]">>]),
    iolist_to_binary(io_lib:format(
        "{\"agent_id\":\"~s\",\"session_id\":\"~s\",\"node\":\"~s\","
        "\"connected_at\":~b,\"plugins\":~s}",
        [AgentId, SessionId, Node, ConnAt, PluginsJson]
    )).

%% @doc Escape a binary string for safe inclusion in JSON output.
-spec json_escape(binary()) -> binary().
json_escape(Bin) when is_binary(Bin) ->
    json_escape_chars(Bin, <<>>).

json_escape_chars(<<>>, Acc) ->
    Acc;
json_escape_chars(<<$", Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, $\\, $">>);
json_escape_chars(<<$\\, Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, $\\, $\\>>);
json_escape_chars(<<$\n, Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, $\\, $n>>);
json_escape_chars(<<$\r, Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, $\\, $r>>);
json_escape_chars(<<$\t, Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, $\\, $t>>);
json_escape_chars(<<C, Rest/binary>>, Acc) when C < 16#20 ->
    Hex = list_to_binary(io_lib:format("\\u~4.16.0b", [C])),
    json_escape_chars(Rest, <<Acc/binary, Hex/binary>>);
json_escape_chars(<<C, Rest/binary>>, Acc) ->
    json_escape_chars(Rest, <<Acc/binary, C>>).

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
