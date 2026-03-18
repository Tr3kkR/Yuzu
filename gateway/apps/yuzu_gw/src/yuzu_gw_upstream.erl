%%%-------------------------------------------------------------------
%%% @doc gRPC client pool to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Heartbeat (batched), Inventory, and stream
%%% status notifications to the upstream server.
%%%
%%% Heartbeats are batched: individual agent heartbeats are buffered
%%% and sent in a single BatchHeartbeat RPC at a configurable interval,
%%% reducing upstream load from O(agents/interval) to O(nodes/interval).
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

-record(state, {
    channel       :: grpcbox_channel:t() | undefined,
    upstream_addr :: string(),
    upstream_port :: non_neg_integer(),
    hb_buffer     :: [map()],           %% buffered heartbeat requests
    hb_timer      :: reference() | undefined,
    hb_interval   :: non_neg_integer()  %% ms
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
    Addr = application:get_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    Port = application:get_env(yuzu_gw, upstream_port, 50050),
    Interval = application:get_env(yuzu_gw, heartbeat_batch_interval_ms, 10000),

    %% Connect to upstream C++ server.
    Channel = connect_upstream(Addr, Port),

    TRef = erlang:send_after(Interval, self(), flush_heartbeats),

    logger:info("Upstream client started, target=~s:~b, hb_interval=~bms",
                [Addr, Port, Interval]),

    {ok, #state{
        channel       = Channel,
        upstream_addr = Addr,
        upstream_port = Port,
        hb_buffer     = [],
        hb_timer      = TRef,
        hb_interval   = Interval
    }}.

handle_call({proxy_register, RegisterReq}, _From, #state{channel = Channel} = State) ->
    Result = do_rpc(Channel, 'ProxyRegister', RegisterReq, register),
    {reply, Result, State};

handle_call({proxy_inventory, InventoryReport}, _From, #state{channel = Channel} = State) ->
    Result = do_rpc(Channel, 'ProxyInventory', InventoryReport, inventory),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({queue_heartbeat, HbReq}, #state{hb_buffer = Buf} = State) ->
    {noreply, State#state{hb_buffer = [HbReq | Buf]}};

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr},
            #state{channel = Channel} = State) ->
    Notification = #{
        agent_id     => AgentId,
        session_id   => ensure_binary(SessionId),
        event        => case Event of connected -> 'CONNECTED'; disconnected -> 'DISCONNECTED' end,
        peer_addr    => PeerAddr,
        gateway_node => atom_to_binary(node(), utf8)
    },
    %% Fire-and-forget: stream status is best-effort.
    spawn(fun() ->
        case do_rpc(Channel, 'NotifyStreamStatus', Notification, notify_stream) of
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

handle_info(flush_heartbeats, #state{hb_buffer = Buf, channel = Channel,
                                       hb_interval = Interval} = State) ->
    BatchReq = #{
        heartbeats   => lists:reverse(Buf),
        gateway_node => atom_to_binary(node(), utf8)
    },

    StartTime = erlang:monotonic_time(millisecond),
    case do_rpc(Channel, 'BatchHeartbeat', BatchReq, batch_heartbeat) of
        {ok, #{acknowledged_count := Count}} ->
            Duration = erlang:monotonic_time(millisecond) - StartTime,
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => <<"BatchHeartbeat">>}),
            logger:debug("Flushed ~b heartbeats (ack=~b)", [length(Buf), Count]);
        {ok, _} ->
            ok;
        {error, Reason} ->
            logger:warning("BatchHeartbeat failed (~b buffered): ~p",
                           [length(Buf), Reason]),
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"BatchHeartbeat">>, code => Reason})
    end,

    TRef = erlang:send_after(Interval, self(), flush_heartbeats),
    {noreply, State#state{hb_buffer = [], hb_timer = TRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

connect_upstream(Addr, Port) ->
    Endpoint = #{scheme => http, host => Addr, port => Port},
    case grpcbox_channel:pick(Endpoint, #{}) of
        {ok, Channel} -> Channel;
        {error, _} ->
            %% Channel will be lazily connected on first RPC.
            logger:warning("Could not pre-connect to upstream ~s:~b", [Addr, Port]),
            Endpoint
    end.

%% Map each GatewayUpstream RPC to its protobuf input/output message types.
rpc_types('ProxyRegister')      -> {'yuzu.agent.v1.RegisterRequest',
                                    'yuzu.agent.v1.RegisterResponse'};
rpc_types('BatchHeartbeat')     -> {'yuzu.gateway.v1.BatchHeartbeatRequest',
                                    'yuzu.gateway.v1.BatchHeartbeatResponse'};
rpc_types('ProxyInventory')     -> {'yuzu.agent.v1.InventoryReport',
                                    'yuzu.agent.v1.InventoryAck'};
rpc_types('NotifyStreamStatus') -> {'yuzu.gateway.v1.StreamStatusNotification',
                                    'yuzu.gateway.v1.StreamStatusAck'}.

do_rpc(_Channel, Method, Request, Tag) ->
    {InputType, OutputType} = rpc_types(Method),
    Def = #grpcbox_def{
        service       = 'yuzu.gateway.v1.GatewayUpstream',
        message_type  = atom_to_binary(InputType, utf8),
        marshal_fun   = fun(Msg) -> gateway_pb:encode_msg(Msg, InputType) end,
        unmarshal_fun = fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end
    },
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/", (atom_to_binary(Method, utf8))/binary>>,
    StartTime = erlang:monotonic_time(millisecond),
    %% Use ctx:background() as context; default_channel is selected via grpcbox_client
    %% get_channel(Options, unary) which defaults to the 'default_channel' atom when
    %% no 'channel' key is in Options.
    Result = grpcbox_client:unary(ctx:background(), Path, Request, Def, #{}),
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
