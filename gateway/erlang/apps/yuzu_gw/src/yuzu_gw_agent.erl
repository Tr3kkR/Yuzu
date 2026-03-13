%%%-------------------------------------------------------------------
%%% @doc gen_statem: one Erlang process per connected agent.
%%%
%%% States:
%%%   connecting   → Register forwarded upstream, awaiting session_id
%%%   streaming    → bidi stream active, agent process owns the writer
%%%   disconnected → cleanup, deregister, terminate
%%%
%%% The process mailbox replaces the C++ stream_write_mu_ — all writes
%%% to this agent's gRPC stream are serialised through message passing.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent).
-behaviour(gen_statem).

%% API
-export([start_link/1,
         dispatch/3,
         get_info/1,
         disconnect/1]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
-export([connecting/3, streaming/3, disconnected/3]).

-record(data, {
    agent_id    :: binary(),
    session_id  :: binary() | undefined,
    stream_ref  :: grpcbox_client:stream() | undefined,
    agent_info  :: map(),
    plugins     :: [binary()],
    pending     :: #{binary() => {pid(), reference()}},  %% command_id => {reply_to, mon_ref}
    connected_at :: integer() | undefined,
    peer_addr   :: binary()
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

%% @doc Dispatch a command to this agent. Called by the router.
-spec dispatch(pid(), map(), {pid(), reference()}) -> ok.
dispatch(Pid, CommandReq, ReplyTo) ->
    gen_statem:cast(Pid, {dispatch, CommandReq, ReplyTo}).

%% @doc Get agent info (synchronous, for dashboard queries).
-spec get_info(pid()) -> {ok, map()} | {error, term()}.
get_info(Pid) ->
    gen_statem:call(Pid, get_info, 5000).

%% @doc Request graceful disconnect.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() -> state_functions.

init(#{agent_id := AgentId, agent_info := AgentInfo,
       stream_ref := StreamRef, peer_addr := PeerAddr} = Args) ->
    SessionId = maps:get(session_id, Args, undefined),
    Plugins = extract_plugin_names(AgentInfo),
    Data = #data{
        agent_id    = AgentId,
        session_id  = SessionId,
        stream_ref  = StreamRef,
        agent_info  = AgentInfo,
        plugins     = Plugins,
        pending     = #{},
        connected_at = erlang:system_time(millisecond),
        peer_addr   = PeerAddr
    },

    %% Register in routing table and join pg groups.
    yuzu_gw_registry:register_agent(AgentId, self(), SessionId, Plugins),

    telemetry:execute([yuzu, gw, agent, connected],
                      #{count => 1},
                      #{agent_id => AgentId, node => node(),
                        session_id => SessionId}),

    logger:info("Agent ~s connected from ~s (session=~s)",
                [AgentId, PeerAddr, SessionId]),

    %% Notify C++ server about the stream connection.
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr),

    case StreamRef of
        undefined -> {ok, connecting, Data};
        _         -> {ok, streaming, Data}
    end.

%%--------------------------------------------------------------------
%% State: connecting
%%--------------------------------------------------------------------

connecting(cast, {stream_ready, StreamRef}, Data) ->
    {next_state, streaming, Data#data{stream_ref = StreamRef,
                                       connected_at = erlang:system_time(millisecond)}};

connecting(cast, {dispatch, _CommandReq, {ReplyTo, _Ref}}, _Data) ->
    %% Cannot dispatch while still connecting — reject immediately.
    ReplyTo ! {command_error, not_connected},
    keep_state_and_data;

connecting({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, format_info(Data, connecting)}}]};

connecting(info, {grpc_closed, _Ref}, Data) ->
    {next_state, disconnected, Data};

connecting(cast, disconnect, Data) ->
    {next_state, disconnected, Data}.

%%--------------------------------------------------------------------
%% State: streaming — the hot path
%%--------------------------------------------------------------------

streaming(cast, {dispatch, CommandReq, {ReplyTo, FanoutRef}}, Data) ->
    #data{stream_ref = StreamRef, agent_id = AgentId, pending = Pending} = Data,
    CmdId = maps:get(<<"command_id">>, CommandReq, maps:get(command_id, CommandReq, undefined)),

    case grpcbox_client:send(StreamRef, CommandReq) of
        ok ->
            Plugin = maps:get(<<"plugin">>, CommandReq,
                              maps:get(plugin, CommandReq, <<"unknown">>)),
            telemetry:execute([yuzu, gw, command, dispatched],
                              #{count => 1},
                              #{agent_id => AgentId, plugin => Plugin,
                                command_id => CmdId}),
            Pending2 = Pending#{CmdId => {ReplyTo, FanoutRef}},
            {keep_state, Data#data{pending = Pending2}};

        {error, Reason} ->
            logger:warning("Stream write failed for agent ~s cmd ~s: ~p",
                           [AgentId, CmdId, Reason]),
            telemetry:execute([yuzu, gw, stream, write_error],
                              #{count => 1},
                              #{agent_id => AgentId, error => Reason}),
            ReplyTo ! {command_error, {stream_write_failed, Reason}},
            {next_state, disconnected, Data}
    end;

streaming(info, {grpc_data, _StreamRef, ResponseFrame}, Data) ->
    #data{agent_id = AgentId, pending = Pending} = Data,
    CmdId = maps:get(<<"command_id">>, ResponseFrame,
                     maps:get(command_id, ResponseFrame, undefined)),
    Status = maps:get(<<"status">>, ResponseFrame,
                      maps:get(status, ResponseFrame, undefined)),

    case maps:find(CmdId, Pending) of
        {ok, {ReplyTo, FanoutRef}} ->
            ReplyTo ! {command_response, FanoutRef, AgentId, ResponseFrame},

            Pending2 = case Status of
                'RUNNING'          -> Pending;
                <<"RUNNING">>      -> Pending;
                0                  -> Pending;  %% proto enum value
                _FinalStatus       ->
                    telemetry:execute([yuzu, gw, command, completed],
                                      #{duration_ms => 0},
                                      #{agent_id => AgentId, status => Status}),
                    maps:remove(CmdId, Pending)
            end,
            {keep_state, Data#data{pending = Pending2}};

        error ->
            logger:debug("Orphaned response from ~s for cmd ~s", [AgentId, CmdId]),
            keep_state_and_data
    end;

streaming(info, {grpc_trailers, _StreamRef, _Trailers}, _Data) ->
    %% Server sent trailers — stream is ending.
    keep_state_and_data;

streaming(info, {grpc_closed, _StreamRef}, Data) ->
    {next_state, disconnected, Data};

streaming(info, {grpc_error, _StreamRef, Reason}, Data) ->
    logger:warning("Stream error for agent ~s: ~p", [Data#data.agent_id, Reason]),
    {next_state, disconnected, Data};

streaming({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, format_info(Data, streaming)}}]};

streaming(cast, disconnect, Data) ->
    #data{stream_ref = StreamRef} = Data,
    catch grpcbox_client:close_send(StreamRef),
    {next_state, disconnected, Data}.

%%--------------------------------------------------------------------
%% State: disconnected — cleanup and terminate
%%--------------------------------------------------------------------

disconnected(enter, _OldState, Data) ->
    do_cleanup(Data),
    {stop, normal, Data};

disconnected(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%--------------------------------------------------------------------
%% terminate
%%--------------------------------------------------------------------

terminate(_Reason, _State, Data) ->
    do_cleanup(Data),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

do_cleanup(#data{agent_id = AgentId, session_id = SessionId,
                  connected_at = ConnectedAt, pending = Pending,
                  peer_addr = PeerAddr}) ->
    %% Deregister from routing table and pg groups.
    yuzu_gw_registry:deregister_agent(AgentId),

    %% Notify pending command waiters that the agent disconnected.
    maps:foreach(fun(_CmdId, {ReplyTo, FanoutRef}) ->
        ReplyTo ! {command_error, FanoutRef, AgentId, agent_disconnected}
    end, Pending),

    Duration = case ConnectedAt of
        undefined -> 0;
        T         -> erlang:system_time(millisecond) - T
    end,

    telemetry:execute([yuzu, gw, agent, disconnected],
                      #{count => 1, duration_ms => Duration},
                      #{agent_id => AgentId, reason => normal}),

    %% Notify C++ server.
    yuzu_gw_upstream:notify_stream_status(AgentId,
                                           SessionId,
                                           disconnected,
                                           PeerAddr),

    logger:info("Agent ~s disconnected (was connected ~bms)", [AgentId, Duration]),
    ok.

extract_plugin_names(AgentInfo) ->
    Plugins = maps:get(<<"plugins">>, AgentInfo,
                       maps:get(plugins, AgentInfo, [])),
    [maps:get(<<"name">>, P, maps:get(name, P, <<"unknown">>)) || P <- Plugins].

format_info(#data{agent_id = AgentId, session_id = SessionId,
                   plugins = Plugins, connected_at = ConnectedAt,
                   agent_info = AgentInfo, peer_addr = PeerAddr,
                   pending = Pending}, State) ->
    #{agent_id     => AgentId,
      session_id   => SessionId,
      state        => State,
      plugins      => Plugins,
      connected_at => ConnectedAt,
      peer_addr    => PeerAddr,
      agent_info   => AgentInfo,
      pending_cmds => maps:size(Pending)}.
