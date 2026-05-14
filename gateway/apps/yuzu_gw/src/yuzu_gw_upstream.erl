%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Inventory, and stream status notifications
%%% to the upstream server.
%%%
%%% Includes a circuit breaker to prevent cascading failures when the
%%% upstream server is unreachable. States:
%%%   closed    — RPCs pass through; consecutive failures tracked
%%%   open      — RPCs fail immediately with {error, circuit_open}
%%%   half_open — one probe RPC allowed; success closes, failure reopens
%%%
%%% Registration replay on reconnect:
%%%   When the upstream connection re-establishes after a failure, the
%%%   C++ server may be a fresh instance with an empty agent registry —
%%%   but the gateway still holds the agent connections. Without a
%%%   replay, those agents are silently stranded (invisible to the
%%%   server) until they happen to reconnect. So on any RPC success
%%%   that follows a period of failures (the half_open -> closed
%%%   transition, or a closed-state success with a non-zero failure
%%%   counter), we re-proxy a ProxyRegister for every agent the
%%%   registry currently holds. The replay is a self-paced drip — one
%%%   agent per scheduled message, spaced by replay_spacing_ms — so a
%%%   fleet of N agents cannot block the gen_server or re-trip the
%%%   circuit breaker. Replay RPCs still pass through the breaker, so a
%%%   server that disappears again mid-replay fails fast and the drip
%%%   stops; the next genuine recovery restarts it.
%%%
%%% Configuration (sys.config / application env):
%%%   circuit_breaker_failure_threshold   — consecutive failures to trip (default 5)
%%%   circuit_breaker_reset_timeout_ms    — initial open duration (default 10000)
%%%   circuit_breaker_max_reset_timeout_ms — max backoff cap (default 300000)
%%%   registration_replay_spacing_ms      — gap between replay RPCs (default 20)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream).
-behaviour(gen_server).

-include_lib("grpcbox/include/grpcbox.hrl").

%% API
-export([start_link/0,
         proxy_register/1,
         proxy_inventory/1,
         notify_stream_status/4,
         circuit_state/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(MAX_NOTIFY_INFLIGHT, 10).
-define(DEFAULT_CB_THRESHOLD, 5).
-define(DEFAULT_CB_RESET_MS, 10000).
-define(DEFAULT_CB_MAX_RESET_MS, 300000).
-define(DEFAULT_REPLAY_SPACING_MS, 20).

-record(state, {
    notify_pids     :: #{pid() => true},
    %% Circuit breaker state
    cb_state        :: closed | open | half_open,
    cb_failures     :: non_neg_integer(),
    cb_threshold    :: non_neg_integer(),
    cb_base_timeout :: non_neg_integer(),
    cb_max_timeout  :: non_neg_integer(),
    cb_cur_timeout  :: non_neg_integer(),
    cb_timer        :: reference() | undefined,
    %% Registration replay on upstream reconnect
    replay_spacing  :: non_neg_integer(),
    replay_queue    :: [{binary(), map()}]  %% agents still to re-proxy ([] = idle)
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

%% @doc Query the current circuit breaker state (for health checks).
-spec circuit_state() -> closed | open | half_open.
circuit_state() ->
    gen_server:call(?SERVER, circuit_state, 5000).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Threshold  = application:get_env(yuzu_gw, circuit_breaker_failure_threshold, ?DEFAULT_CB_THRESHOLD),
    BaseTimeout = application:get_env(yuzu_gw, circuit_breaker_reset_timeout_ms, ?DEFAULT_CB_RESET_MS),
    MaxTimeout  = application:get_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, ?DEFAULT_CB_MAX_RESET_MS),
    ReplaySpacing = application:get_env(yuzu_gw, registration_replay_spacing_ms, ?DEFAULT_REPLAY_SPACING_MS),

    logger:info("Upstream client started (circuit breaker: threshold=~b, base_timeout=~bms, "
                "replay_spacing=~bms)",
                [Threshold, BaseTimeout, ReplaySpacing]),

    {ok, #state{
        notify_pids     = #{},
        cb_state        = closed,
        cb_failures     = 0,
        cb_threshold    = Threshold,
        cb_base_timeout = BaseTimeout,
        cb_max_timeout  = MaxTimeout,
        cb_cur_timeout  = BaseTimeout,
        cb_timer        = undefined,
        replay_spacing  = ReplaySpacing,
        replay_queue    = []
    }}.

handle_call(circuit_state, _From, #state{cb_state = CbState} = State) ->
    {reply, CbState, State};

handle_call({proxy_register, RegisterReq}, _From, State) ->
    case check_circuit(State) of
        {reject, State1} ->
            {reply, {error, circuit_open}, State1};
        {allow, State1} ->
            Result = do_rpc('ProxyRegister', RegisterReq, register),
            State2 = record_result(Result, State1),
            {reply, Result, State2}
    end;

handle_call({proxy_inventory, InventoryReport}, _From, State) ->
    case check_circuit(State) of
        {reject, State1} ->
            {reply, {error, circuit_open}, State1};
        {allow, State1} ->
            Result = do_rpc('ProxyInventory', InventoryReport, inventory),
            State2 = record_result(Result, State1),
            {reply, Result, State2}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr},
            #state{notify_pids = Pids, cb_state = CbState} = State) ->
    %% Don't spawn notifications if circuit is open
    case CbState of
        open ->
            logger:debug("Dropping stream status notification for ~s (circuit open)", [AgentId]),
            {noreply, State};
        _ ->
            case map_size(Pids) >= ?MAX_NOTIFY_INFLIGHT of
                true ->
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
            end
    end;

handle_cast(replay_registrations, State) ->
    %% Snapshot the agents the registry currently holds and (re)seed the
    %% replay queue. Reading the registry here — not at recovery-detect
    %% time — means an agent that disconnected during the outage is
    %% already gone from ETS and will not be replayed. If a drip is
    %% already running, this just refreshes the queue with the latest
    %% snapshot; the running replay_next will pick it up.
    Agents = yuzu_gw_registry:all_register_reqs(),
    case Agents of
        [] ->
            logger:info("Registration replay: no agents to re-proxy"),
            {noreply, State#state{replay_queue = []}};
        _ ->
            WasIdle = State#state.replay_queue =:= [],
            logger:info("Registration replay: re-proxying ~b agent(s) upstream",
                        [length(Agents)]),
            State1 = State#state{replay_queue = Agents},
            %% Only kick a fresh drip if one wasn't already in flight —
            %% otherwise two replay_next loops would race the queue.
            case WasIdle of
                true  -> self() ! replay_next;
                false -> ok
            end,
            {noreply, State1}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Drip one agent off the replay queue per message. Each step re-proxies
%% exactly one ProxyRegister (through the circuit breaker) then schedules
%% the next after replay_spacing ms — so a fleet of N agents never blocks
%% the gen_server and a server that vanishes again mid-replay fails fast.
handle_info(replay_next, #state{replay_queue = []} = State) ->
    %% Queue drained — replay complete.
    {noreply, State};
handle_info(replay_next, #state{replay_queue = [{AgentId, RegisterReq} | Rest],
                                replay_spacing = Spacing} = State) ->
    State2 =
        case check_circuit(State) of
            {reject, State1} ->
                %% Circuit reopened during replay — the upstream went
                %% away again. Abandon the drip; the next genuine
                %% recovery (half_open -> closed) will reseed and
                %% restart it from a fresh registry snapshot.
                logger:warning("Registration replay aborted: circuit open "
                               "(~b agent(s) not yet re-proxied)", [length(Rest) + 1]),
                State1#state{replay_queue = []};
            {allow, State1} ->
                case map_size(RegisterReq) of
                    0 ->
                        %% Agent registered without a stashed request
                        %% (older caller / test). Nothing to send — skip
                        %% it without disturbing the breaker.
                        logger:debug("Registration replay: skipping ~s (no stored request)",
                                     [AgentId]),
                        schedule_replay_next(Rest, Spacing),
                        State1#state{replay_queue = Rest};
                    _ ->
                        Result = do_rpc('ProxyRegister', RegisterReq, register),
                        case Result of
                            {ok, _} ->
                                logger:debug("Registration replay: re-proxied ~s", [AgentId]);
                            {error, Reason} ->
                                logger:warning("Registration replay: ~s failed: ~p",
                                               [AgentId, Reason])
                        end,
                        %% Feed the result through the breaker so a
                        %% mid-replay failure trips/advances it normally —
                        %% but record_result_no_replay so a successful
                        %% replay RPC can't kick off a nested replay.
                        State3 = record_result_no_replay(Result, State1),
                        schedule_replay_next(Rest, Spacing),
                        State3#state{replay_queue = Rest}
                end
        end,
    {noreply, State2};

handle_info(circuit_half_open, State) ->
    logger:info("Circuit breaker: open -> half_open (allowing probe RPC)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"half_open">>}),
    {noreply, State#state{cb_state = half_open, cb_timer = undefined}};

handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids} = State) ->
    {noreply, State#state{notify_pids = maps:remove(Pid, Pids)}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Circuit breaker logic
%%%===================================================================

%% @doc Check if the circuit allows an RPC to proceed.
check_circuit(#state{cb_state = closed} = State) ->
    {allow, State};
check_circuit(#state{cb_state = half_open} = State) ->
    %% Allow exactly one probe RPC
    {allow, State};
check_circuit(#state{cb_state = open} = State) ->
    {reject, State}.

%% @doc Record the result of an RPC and update circuit breaker state.
%%
%% An RPC success that follows a period of failures means the upstream
%% connection has re-established — possibly against a fresh server with
%% an empty registry. on_success/1 flags that case; record_result/2
%% then casts replay_registrations to self so the agents the gateway
%% already holds get re-proxied. The cast (not an inline call) keeps
%% the replay off the hot path of whatever RPC just succeeded.
record_result({ok, _}, State) ->
    case on_success(State) of
        {State1, replay} ->
            gen_server:cast(self(), replay_registrations),
            State1;
        {State1, noop} ->
            State1
    end;
record_result({error, _}, State) ->
    on_failure(State).

%% @doc Like record_result/2 but never triggers a registration replay.
%% Used by the replay drip itself: a replay RPC must still advance the
%% circuit breaker (so a mid-replay outage trips it), but it must not
%% kick off a second, nested replay cascade.
record_result_no_replay({ok, _}, State) ->
    {State1, _Trigger} = on_success(State),
    State1;
record_result_no_replay({error, _}, State) ->
    on_failure(State).

%% @doc Returns {NewState, replay | noop}. `replay' means an RPC just
%% succeeded after one or more failures — treat it as a reconnect.
on_success(#state{cb_state = closed, cb_failures = 0} = State) ->
    %% Steady state — nothing recovered.
    {State, noop};
on_success(#state{cb_state = closed} = State) ->
    %% Closed but cb_failures > 0: the upstream had failing RPCs and is
    %% now answering again, yet never accumulated enough consecutive
    %% failures to trip the breaker. This is the common server-bounce
    %% case (few/idle agents, short outage) — replay so the freshly
    %% restarted server relearns every agent.
    logger:info("Upstream recovered (closed, ~b prior failures) — "
                "scheduling registration replay", [State#state.cb_failures]),
    {State#state{cb_failures = 0}, replay};
on_success(#state{cb_state = half_open, cb_base_timeout = BaseTimeout} = State) ->
    %% Probe succeeded — close the circuit, reset backoff. The breaker
    %% fully tripped, so the upstream was definitely down; replay.
    logger:info("Circuit breaker: half_open -> closed (probe succeeded) — "
                "scheduling registration replay"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"closed">>}),
    {State#state{
        cb_state      = closed,
        cb_failures   = 0,
        cb_cur_timeout = BaseTimeout
    }, replay}.

on_failure(#state{cb_state = closed, cb_failures = F, cb_threshold = T} = State) ->
    NewF = F + 1,
    case NewF >= T of
        true  -> trip_circuit(State#state{cb_failures = NewF});
        false -> State#state{cb_failures = NewF}
    end;
on_failure(#state{cb_state = half_open} = State) ->
    %% Probe failed — reopen with doubled timeout
    logger:warning("Circuit breaker: half_open -> open (probe failed, increasing backoff)"),
    trip_circuit(State).

trip_circuit(#state{cb_cur_timeout = CurTimeout, cb_max_timeout = MaxTimeout} = State) ->
    %% Cancel any existing timer
    cancel_timer(State#state.cb_timer),

    %% Exponential backoff: double the timeout, capped at max
    NewTimeout = min(CurTimeout * 2, MaxTimeout),
    TRef = erlang:send_after(CurTimeout, self(), circuit_half_open),

    logger:warning("Circuit breaker: OPEN (will probe in ~bms)", [CurTimeout]),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"open">>}),

    State#state{
        cb_state      = open,
        cb_cur_timeout = NewTimeout,
        cb_timer      = TRef
    }.

cancel_timer(undefined) -> ok;
cancel_timer(TRef) -> erlang:cancel_timer(TRef).

%% @doc Schedule the next replay step, unless the queue is now empty.
%% Spacing the steps keeps each handle_info short and rate-limits the
%% ProxyRegister fan-out so a fleet of N agents can't trip the breaker.
schedule_replay_next([], _Spacing) ->
    ok;
schedule_replay_next(_Rest, Spacing) ->
    erlang:send_after(Spacing, self(), replay_next),
    ok.

%%%===================================================================
%%% Internal — RPC execution
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
