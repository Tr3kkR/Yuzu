%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Heartbeat (batched), Inventory, and stream
%%% status notifications to the upstream server.
%%%
%%% Heartbeats are batched: individual agent heartbeats are buffered
%%% and sent in a single BatchHeartbeat RPC at a configurable interval,
%%% reducing upstream load from O(agents/interval) to O(nodes/interval).
%%%
%%% On RPC failure, heartbeat buffers are retained (capped) for retry
%%% on the next flush cycle rather than being silently discarded.
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
         queue_heartbeat/1,
         proxy_inventory/1,
         notify_stream_status/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_MAX_HB_BUFFER, 10000).

-record(state, {
    hb_buffer     :: [map()],           %% buffered heartbeat requests
    hb_timer      :: reference() | undefined,
    hb_interval   :: non_neg_integer(), %% ms
    max_hb_buffer :: non_neg_integer()  %% cap for retained buffer on failure
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

%% @doc Queue a heartbeat for batching.
-spec queue_heartbeat(map()) -> ok.
queue_heartbeat(HeartbeatReq) ->
    gen_server:cast(?SERVER, {queue_heartbeat, HeartbeatReq}).

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
    Interval = application:get_env(yuzu_gw, heartbeat_batch_interval_ms, 10000),
    MaxBuf = application:get_env(yuzu_gw, max_heartbeat_buffer, ?DEFAULT_MAX_HB_BUFFER),

    TRef = erlang:send_after(Interval, self(), flush_heartbeats),

    logger:info("Upstream client started, hb_interval=~bms, max_buf=~b",
                [Interval, MaxBuf]),

    {ok, #state{
        hb_buffer     = [],
        hb_timer      = TRef,
        hb_interval   = Interval,
        max_hb_buffer = MaxBuf
    }}.

handle_call({proxy_register, RegisterReq}, _From, State) ->
    Result = do_rpc('ProxyRegister', RegisterReq, register),
    {reply, Result, State};

handle_call({proxy_inventory, InventoryReport}, _From, State) ->
    Result = do_rpc('ProxyInventory', InventoryReport, inventory),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({queue_heartbeat, HbReq}, #state{hb_buffer = Buf} = State) ->
    {noreply, State#state{hb_buffer = [HbReq | Buf]}};

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr},
            State) ->
    Notification = #{
        agent_id     => AgentId,
        session_id   => ensure_binary(SessionId),
        event        => case Event of connected -> 'CONNECTED'; disconnected -> 'DISCONNECTED' end,
        peer_addr    => PeerAddr,
        gateway_node => atom_to_binary(node(), utf8)
    },
    %% Fire-and-forget: stream status is best-effort.
    spawn(fun() ->
        case do_rpc('NotifyStreamStatus', Notification, notify_stream) of
            {ok, _} -> ok;
            {error, Reason} ->
                logger:warning("Failed to notify stream status for ~s: ~p",
                               [AgentId, Reason])
        end
    end),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(flush_heartbeats, #state{hb_buffer = [], hb_interval = Interval} = State) ->
    TRef = erlang:send_after(Interval, self(), flush_heartbeats),
    {noreply, State#state{hb_timer = TRef}};

handle_info(flush_heartbeats, #state{hb_buffer = Buf, hb_interval = Interval,
                                       max_hb_buffer = MaxBuf} = State) ->
    BatchReq = #{
        heartbeats   => lists:reverse(Buf),
        gateway_node => atom_to_binary(node(), utf8)
    },

    NewBuf = case do_rpc('BatchHeartbeat', BatchReq, batch_heartbeat) of
        {ok, #{acknowledged_count := Count}} ->
            logger:debug("Flushed ~b heartbeats (ack=~b)", [length(Buf), Count]),
            [];
        {ok, _} ->
            [];
        {error, Reason} ->
            logger:warning("BatchHeartbeat failed (~b buffered): ~p",
                           [length(Buf), Reason]),
            %% Retain buffer for retry, capped to prevent unbounded growth.
            case length(Buf) > MaxBuf of
                true  -> lists:sublist(Buf, MaxBuf);
                false -> Buf
            end
    end,

    TRef = erlang:send_after(Interval, self(), flush_heartbeats),
    {noreply, State#state{hb_buffer = NewBuf, hb_timer = TRef}};

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
rpc_types('BatchHeartbeat')     -> {'yuzu.gateway.v1.BatchHeartbeatRequest',
                                    'yuzu.gateway.v1.BatchHeartbeatResponse'};
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
            {error, Reason}
    end.

ensure_binary(undefined) -> <<>>;
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) -> list_to_binary(L).
