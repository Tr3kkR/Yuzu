%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Inventory, and stream status notifications
%%% to the upstream server. All are synchronous or fire-and-forget RPCs.
%%%
%%% Heartbeat buffering has been moved to yuzu_gw_heartbeat_buffer
%%% to prevent registration storms from blocking heartbeat processing.
%%%
%%% Upstream connection is managed by grpcbox via the `default_channel`
%%% configured in sys.config.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream).
-behaviour(gen_server).

-include_lib("grpcbox/include/grpcbox.hrl").

%% API
-export([start_link/0,
         proxy_register/1,
         proxy_inventory/1,
         notify_stream_status/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).
-define(MAX_NOTIFY_INFLIGHT, 10).

-record(state, {
    notify_pids   :: #{pid() => true}   %% in-flight notification processes
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Forward a RegisterRequest to the C++ server.
-spec proxy_register(map()) -> {ok, map()} | {error, term()}.
proxy_register(RegisterReq) ->
    gen_server:call(?SERVER, {proxy_register, RegisterReq}, 30000).

%% @doc Forward an InventoryReport to the C++ server.
-spec proxy_inventory(map()) -> {ok, map()} | {error, term()}.
proxy_inventory(InventoryReport) ->
    gen_server:call(?SERVER, {proxy_inventory, InventoryReport}, 30000).

%% @doc Notify C++ server about agent stream connect/disconnect.
-spec notify_stream_status(binary(), binary() | undefined, connected | disconnected, binary()) -> ok.
notify_stream_status(AgentId, SessionId, Event, PeerAddr) ->
    gen_server:cast(?SERVER, {notify_stream_status, AgentId, SessionId, Event, PeerAddr}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    logger:info("Upstream client started (register/inventory/notify only)"),
    {ok, #state{notify_pids = #{}}}.

handle_call({proxy_register, RegisterReq}, _From, State) ->
    Result = do_rpc('ProxyRegister', RegisterReq, register),
    {reply, Result, State};

handle_call({proxy_inventory, InventoryReport}, _From, State) ->
    Result = do_rpc('ProxyInventory', InventoryReport, inventory),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr},
            #state{notify_pids = Pids} = State) ->
    case map_size(Pids) >= ?MAX_NOTIFY_INFLIGHT of
        true ->
            %% At capacity — drop this notification (best-effort).
            logger:debug("Dropping stream status notification for ~s (at capacity)", [AgentId]),
            {noreply, State};
        false ->
            Notification = #{
                agent_id     => AgentId,
                session_id   => ensure_binary(SessionId),
                event        => case Event of connected -> 'CONNECTED'; disconnected -> 'DISCONNECTED' end,
                peer_addr    => PeerAddr,
                gateway_node => atom_to_binary(node(), utf8)
            },
            {Pid, _MonRef} = spawn_monitor(fun() ->
                case do_rpc('NotifyStreamStatus', Notification, notify_stream) of
                    {ok, _} -> ok;
                    {error, Reason} ->
                        logger:warning("Failed to notify stream status for ~s: ~p",
                                       [AgentId, Reason])
                end
            end),
            {noreply, State#state{notify_pids = Pids#{Pid => true}}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids} = State) ->
    {noreply, State#state{notify_pids = maps:remove(Pid, Pids)}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

%% Map each GatewayUpstream RPC to its protobuf input/output message types.
rpc_types('ProxyRegister')      -> {'yuzu.agent.v1.RegisterRequest',
                                    'yuzu.agent.v1.RegisterResponse'};
rpc_types('ProxyInventory')     -> {'yuzu.agent.v1.InventoryReport',
                                    'yuzu.agent.v1.InventoryAck'};
rpc_types('NotifyStreamStatus') -> {'yuzu.gateway.v1.StreamStatusNotification',
                                    'yuzu.gateway.v1.StreamStatusAck'}.

do_rpc(Method, Request, Tag) ->
    {InputType, OutputType} = rpc_types(Method),
    Def = #grpcbox_def{
        service       = 'yuzu.gateway.v1.GatewayUpstream',
        message_type  = atom_to_binary(InputType, utf8),
        marshal_fun   = fun(Msg) -> gateway_pb:encode_msg(Msg, InputType) end,
        unmarshal_fun = fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end
    },
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/", (atom_to_binary(Method, utf8))/binary>>,
    StartTime = erlang:monotonic_time(millisecond),
    Result = grpcbox_client:unary(ctx:background(), Path, Request, Def,
                                  #{channel => default_channel}),
    Duration = erlang:monotonic_time(millisecond) - StartTime,
    case Result of
        {ok, Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => atom_to_binary(Tag, utf8)}),
            {ok, Response};
        {error, {Status, Message, _Trailers}} ->
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Status}),
            logger:warning("Upstream RPC ~s failed: ~p ~s", [Method, Status, Message]),
            {error, {Status, Message}};
        {error, Reason} ->
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Reason}),
            {error, {internal, iolist_to_binary(io_lib:format("~p", [Reason]))}}
    end.

ensure_binary(undefined) -> <<>>;
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) -> list_to_binary(L).
