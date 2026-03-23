%%%-------------------------------------------------------------------
%%% @doc yuzu_gw application callback module.
%%%
%%% Starts the top-level supervisor, initialises telemetry handlers,
%%% and creates the pg scope used for cluster-wide agent groups.
%%%
%%% Supports environment variable overrides for container deployments.
%%% See apply_env_overrides/0 for the full list.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([apply_env_overrides/0]).  %% exported for testing

%%--------------------------------------------------------------------
%% application callbacks
%%--------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    %% Apply environment variable overrides (container deployment).
    apply_env_overrides(),

    %% Log TLS state clearly at startup.
    case application:get_env(yuzu_gw, tls_enabled, auto) of
        false ->
            logger:warning("TLS DISABLED — running plaintext (test/dev only)");
        _ ->
            case application:get_env(yuzu_gw, tls, undefined) of
                undefined -> logger:info("TLS: not configured (plaintext)");
                {ok, []}  -> logger:info("TLS: not configured (plaintext)");
                {ok, _}   -> logger:info("TLS: enabled")
            end
    end,

    %% Attach telemetry/prometheus handlers.
    yuzu_gw_telemetry:setup(),

    %% Start Prometheus HTTP exporter for /metrics endpoint.
    Port = application:get_env(yuzu_gw, prometheus_port, 9568),
    application:set_env(prometheus, prometheus_http, [{port, Port}, {path, "/metrics"}]),
    {ok, _} = prometheus_httpd:start(),
    logger:info("Prometheus metrics endpoint started on port ~p", [Port]),

    %% Start the supervision tree.
    yuzu_gw_sup:start_link().

stop(_State) ->
    logger:info("Gateway shutting down — entering drain phase"),

    %% 1. Stop accepting new commands via the router.
    case whereis(yuzu_gw_router) of
        undefined -> ok;
        RouterPid ->
            logger:info("Notifying router to stop accepting new commands"),
            RouterPid ! drain,
            ok
    end,

    %% 2. Wait for in-flight commands to complete (up to 10 seconds).
    DrainDeadline = erlang:monotonic_time(second) + 10,
    drain_pending(DrainDeadline),

    %% 3. Flush heartbeat buffer synchronously.
    logger:info("Flushing heartbeat buffer"),
    try yuzu_gw_heartbeat_buffer:flush_sync()
    catch _:_ ->
        %% Fallback: best-effort async flush.
        try yuzu_gw_heartbeat_buffer:queue_heartbeat(flush_sentinel)
        catch _:_ -> ok
        end,
        timer:sleep(500)
    end,

    logger:info("Gateway shutdown complete"),
    ok.

%% @private Wait for pending commands to drain or until deadline.
drain_pending(Deadline) ->
    Now = erlang:monotonic_time(second),
    case Now >= Deadline of
        true ->
            logger:warning("Drain deadline reached — proceeding with shutdown");
        false ->
            %% Check if any agent processes still have pending commands.
            %% pg:get_members may fail if pg is already shutting down.
            Agents = try pg:get_members(yuzu_gw, all_agents) catch _:_ -> [] end,
            HasPending = lists:any(fun(Pid) ->
                try gen_statem:call(Pid, pending_count, 1000) > 0
                catch _:_ -> false
                end
            end, Agents),
            case HasPending of
                false ->
                    logger:info("All in-flight commands drained");
                true ->
                    logger:info("Draining: waiting for in-flight commands..."),
                    timer:sleep(1000),
                    drain_pending(Deadline)
            end
    end.

%%--------------------------------------------------------------------
%% Environment variable overrides for container deployment
%%--------------------------------------------------------------------

apply_env_overrides() ->
    Overrides = [
        {"YUZU_GW_UPSTREAM_ADDR",    upstream_addr,    fun(V) -> V end},
        {"YUZU_GW_UPSTREAM_PORT",    upstream_port,    fun list_to_integer/1},
        {"YUZU_GW_AGENT_PORT",       agent_listen_port, fun list_to_integer/1},
        {"YUZU_GW_MGMT_PORT",        mgmt_listen_port,  fun list_to_integer/1},
        {"YUZU_GW_PROMETHEUS_PORT",  prometheus_port,   fun list_to_integer/1},
        {"YUZU_GW_HEALTH_PORT",      health_port,       fun list_to_integer/1},
        {"YUZU_GW_HEARTBEAT_INTERVAL_MS", heartbeat_batch_interval_ms, fun list_to_integer/1},
        {"YUZU_GW_COMMAND_TIMEOUT_S",     default_command_timeout_s,   fun list_to_integer/1},
        {"YUZU_GW_BACKPRESSURE_THRESHOLD", backpressure_threshold,     fun list_to_integer/1},
        {"YUZU_GW_CB_FAILURE_THRESHOLD",   circuit_breaker_failure_threshold, fun list_to_integer/1},
        {"YUZU_GW_CB_RESET_TIMEOUT_MS",    circuit_breaker_reset_timeout_ms,  fun list_to_integer/1},
        {"YUZU_GW_CB_MAX_RESET_TIMEOUT_MS", circuit_breaker_max_reset_timeout_ms, fun list_to_integer/1},
        {"YUZU_GW_TLS_ENABLED", tls_enabled, fun
            ("true")  -> true;
            ("false") -> false;
            ("1")     -> true;
            ("0")     -> false;
            (V)       -> error({bad_bool, V})
        end}
    ],
    lists:foreach(fun({EnvVar, AppKey, ParseFun}) ->
        case os:getenv(EnvVar) of
            false -> ok;
            Value ->
                try
                    Parsed = ParseFun(Value),
                    application:set_env(yuzu_gw, AppKey, Parsed),
                    logger:info("ENV override: ~s = ~p", [EnvVar, Parsed])
                catch
                    _:_ ->
                        logger:warning("ENV override: ~s has invalid value '~s', ignoring",
                                       [EnvVar, Value])
                end
        end
    end, Overrides),

    %% TLS cert overrides (these set the tls proplist)
    apply_tls_overrides().

apply_tls_overrides() ->
    Cert = os:getenv("YUZU_GW_TLS_CERTFILE"),
    Key  = os:getenv("YUZU_GW_TLS_KEYFILE"),
    Ca   = os:getenv("YUZU_GW_TLS_CACERTFILE"),
    case {Cert, Key, Ca} of
        {false, false, false} ->
            ok;  % No TLS env vars — use sys.config values
        _ ->
            Base = application:get_env(yuzu_gw, tls, []),
            TlsOpts0 = case Cert of
                false -> Base;
                C     -> lists:keystore(certfile, 1, Base, {certfile, C})
            end,
            TlsOpts1 = case Key of
                false -> TlsOpts0;
                K     -> lists:keystore(keyfile, 1, TlsOpts0, {keyfile, K})
            end,
            TlsOpts2 = case Ca of
                false -> TlsOpts1;
                A     -> lists:keystore(cacertfile, 1, TlsOpts1, {cacertfile, A})
            end,
            application:set_env(yuzu_gw, tls, TlsOpts2),
            logger:info("TLS config updated from environment variables")
    end.
