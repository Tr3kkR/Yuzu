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
-export([apply_env_overrides/0, evaluate_cookie/3]).  %% exported for testing
-export([client_has_https/1, client_tls_posture/1, servers_have_tls/1]). %% for testing
-export([evaluate_upstream_posture/2]).                                  %% for testing

%%--------------------------------------------------------------------
%% application callbacks
%%--------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    %% #659: refuse to boot with a known-insecure Erlang distribution cookie,
    %% before any side effects. The cookie is the sole authentication for
    %% inter-node RPC; a publicly known value is unauthenticated RCE.
    case check_distribution_cookie() of
        {error, Reason} -> {error, Reason};
        ok              -> do_start()
    end.

do_start() ->
    %% Apply environment variable overrides (container deployment).
    apply_env_overrides(),

    %% Log the ACTUAL transport TLS posture. grpcbox reads its own
    %% {grpcbox, client|servers} config at boot and is the source of truth; the
    %% yuzu_gw `tls`/`tls_enabled` env is advisory only (nothing wires it into
    %% grpcbox — see docs/pki-architecture.md "Gateway TLS"). The previous code
    %% matched `{ok, _}` against application:get_env/3, which returns the bare
    %% value (never `{ok, _}`), so it was dead — and a real `tls` proplist would
    %% have crashed boot with a case_clause.
    log_tls_state(),

    %% #PR5: fail CLOSED on a misconfigured-but-encrypted upstream (https without
    %% verify_peer is MITM-able) — same fail-closed philosophy as the distribution
    %% cookie guard, rather than booting with only a log warning. PLAINTEXT upstream
    %% is still allowed (the legitimate UAT/dev posture); only the "TLS but
    %% unauthenticated" footgun is refused.
    case check_upstream_tls_posture() of
        {error, Reason} ->
            {error, Reason};
        ok ->
            %% Attach telemetry/prometheus handlers.
            yuzu_gw_telemetry:setup(),

            %% Start Prometheus HTTP exporter for /metrics endpoint.
            Port = application:get_env(yuzu_gw, prometheus_port, 9568),
            application:set_env(prometheus, prometheus_http, [{port, Port}, {path, "/metrics"}]),
            {ok, _} = prometheus_httpd:start(),
            logger:info("Prometheus metrics endpoint started on port ~p", [Port]),

            %% Start the supervision tree.
            yuzu_gw_sup:start_link()
    end.

%%--------------------------------------------------------------------
%% Distribution cookie guard (#659)
%%--------------------------------------------------------------------

%% @private Refuse to boot if the Erlang distribution cookie is a known-
%% insecure default. The cookie is the SOLE authentication for inter-node
%% RPC; a publicly known value (the repo's historical default) means
%% unauthenticated remote code execution for anyone who can reach EPMD.
-spec check_distribution_cookie() -> ok | {error, insecure_distribution_cookie}.
check_distribution_cookie() ->
    Allow = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE") =:= "1",
    evaluate_cookie(node(), erlang:get_cookie(), Allow).

%% @doc Pure cookie policy decision — exported for testing.
%% A non-distributed node ('nonode@nohost') has no inter-node attack surface,
%% so any cookie is accepted. Otherwise the known-default and empty cookies
%% are rejected unless explicitly overridden for dev/CI.
-spec evaluate_cookie(node(), atom(), boolean()) ->
          ok | {error, insecure_distribution_cookie}.
evaluate_cookie('nonode@nohost', _Cookie, _Allow) ->
    ok;
evaluate_cookie(_Node, Cookie, Allow) ->
    CookieStr = atom_to_list(Cookie),
    %% Reject (a) the empty cookie, (b) the historical committed default as a
    %% SUBSTRING — so the literal `${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}`
    %% is caught if relx `.src` env-substitution ever fails (missing awk in a
    %% broken/minimal image, or a hand-edited vm.args) — and (c) any
    %% unsubstituted `${...}` env placeholder. Substring (not exact) match is
    %% the #659 UP-1 hardening: an exact-match list would let the unsubstituted
    %% literal through and silently re-open the unauthenticated-RPC surface.
    Insecure = CookieStr =:= ""
        orelse string:find(CookieStr, "yuzu_gw_secret_change_me") =/= nomatch
        orelse string:find(CookieStr, "${") =/= nomatch,
    case {Insecure, Allow} of
        {true, false} ->
            logger:critical(
                "Refusing to start: Erlang distribution cookie is the insecure default. "
                "The cookie is the sole authentication for inter-node RPC; a known value "
                "means unauthenticated remote code execution for anyone who can reach EPMD "
                "(port 4369). Set a strong unique cookie via the YUZU_GW_COOKIE environment "
                "variable (e.g. `openssl rand -hex 32`). Dev/CI may override with "
                "YUZU_GW_ALLOW_DEFAULT_COOKIE=1."),
            {error, insecure_distribution_cookie};
        {true, true} ->
            logger:warning(
                "Erlang distribution cookie is the insecure default, but "
                "YUZU_GW_ALLOW_DEFAULT_COOKIE=1 is set — proceeding (dev/CI only)."),
            ok;
        {false, _} ->
            ok
    end.

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
        %% flush_sync failed (process already down) — allow brief drain.
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

%%--------------------------------------------------------------------
%% TLS posture reporting (PKI PR5)
%%--------------------------------------------------------------------

-type tls_posture() :: verified | unverified | plaintext.

%% @private Report the real transport TLS posture from grpcbox's OWN config —
%% the authoritative source (grpcbox reads {grpcbox, client|servers} at boot,
%% not yuzu_gw's advisory `tls` env). Never crashes on unexpected shapes.
-spec log_tls_state() -> ok.
log_tls_state() ->
    case application:get_env(yuzu_gw, tls_enabled, auto) of
        false ->
            logger:warning("YUZU_GW_TLS_ENABLED=false is advisory only — the actual "
                           "transport is whatever the grpcbox config selects (below)");
        _ -> ok
    end,
    Up = client_tls_posture(application:get_env(grpcbox, client, undefined)),
    Listen = servers_have_tls(application:get_env(grpcbox, servers, undefined)),
    %% This reflects the CONFIGURED grpcbox posture, not a live handshake — the
    %% upstream channel connects lazily (and the server may not have generated
    %% certs yet at boot), so a startup file/handshake probe would false-alarm.
    logger:info("Gateway transport TLS (configured): upstream->server=~s, "
                "listeners(agent/mgmt)=~s", [posture_word(Up), tls_word(Listen)]),
    case Up of
        plaintext ->
            logger:warning("Gateway->server upstream is PLAINTEXT. For production point "
                           "the grpcbox default_channel at {https,...} with the gateway "
                           "leaf + CA (see config/sys.config.prod / deploy gateway-sys.config).");
        unverified ->
            %% https without {verify,verify_peer}: encrypted but NOT authenticated —
            %% an active MITM can impersonate the server. Do not report this as "TLS".
            logger:warning("Gateway->server upstream is ENCRYPTED but does NOT verify the "
                           "server certificate ({verify,verify_peer} missing from the "
                           "grpcbox default_channel SslOpts) — vulnerable to MITM. Add "
                           "{verify,verify_peer} + {cacertfile,...}.");
        verified -> ok
    end,
    %% Advisory-env footgun: an operator who set YUZU_GW_TLS_* populated only the
    %% unconsumed yuzu_gw `tls` env; it does NOT configure grpcbox, REGARDLESS of
    %% the actual upstream posture. Warn whenever it is set so the misconception is
    %% always surfaced (not only when the upstream happens to be plaintext).
    case application:get_env(yuzu_gw, tls, []) of
        [] -> ok;
        _ ->
            logger:warning("yuzu_gw `tls` env is set (YUZU_GW_TLS_*) but those env vars are "
                           "advisory and do NOT configure grpcbox (it reads its own config). "
                           "Set TLS in the grpcbox block of sys.config. See "
                           "docs/pki-architecture.md 'Gateway TLS'.")
    end,
    ok.

%% @private Fail-closed guard: refuse to boot if the grpcbox upstream channel is
%% TLS-but-unverified (https without {verify,verify_peer}) — encrypted yet
%% MITM-able. PLAINTEXT upstream is permitted (the legitimate UAT/dev posture);
%% only the dangerous "looks secure, isn't" middle state is refused. Mirrors the
%% distribution-cookie guard's fail-closed posture. Dev/CI override:
%% YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1.
-spec check_upstream_tls_posture() -> ok | {error, unverified_upstream_tls}.
check_upstream_tls_posture() ->
    Posture = client_tls_posture(application:get_env(grpcbox, client, undefined)),
    Allow = os:getenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM") =:= "1",
    case evaluate_upstream_posture(Posture, Allow) of
        {error, unverified_upstream_tls} ->
            logger:critical(
                "Refusing to start: the grpcbox upstream channel uses TLS (https) WITHOUT "
                "{verify,verify_peer} — encrypted but UNAUTHENTICATED (MITM-able). Add "
                "{verify,verify_peer} + {cacertfile,...} to the default_channel SslOpts "
                "(see config/sys.config.prod). Dev/CI may override with "
                "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1."),
            {error, unverified_upstream_tls};
        ok when Posture =:= unverified ->
            logger:warning("Upstream TLS is unverified (no verify_peer) but "
                           "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1 — proceeding (dev/CI only)."),
            ok;
        ok ->
            ok
    end.

%% @doc Pure upstream-posture policy decision — exported for testing. Only
%% `unverified` (https without verify_peer) without an explicit override is
%% refused; `verified` and `plaintext` boot.
-spec evaluate_upstream_posture(tls_posture(), boolean()) ->
          ok | {error, unverified_upstream_tls}.
evaluate_upstream_posture(unverified, false) -> {error, unverified_upstream_tls};
evaluate_upstream_posture(_Posture, _Allow)  -> ok.

-spec tls_word(boolean()) -> string().
tls_word(true)  -> "TLS";
tls_word(false) -> "plaintext".

-spec posture_word(tls_posture()) -> string().
posture_word(verified)   -> "mutual-TLS";
posture_word(unverified) -> "TLS(UNVERIFIED!)";
posture_word(plaintext)  -> "plaintext".

%% @doc Strongest TLS posture across grpcbox client channels: `verified` (an
%% `https` endpoint with {verify,verify_peer}), `unverified` (https without it),
%% else `plaintext`. Pure; exported for testing.
-spec client_tls_posture(term()) -> tls_posture().
client_tls_posture(#{channels := Channels}) when is_list(Channels) ->
    lists:foldl(fun(Ch, Acc) -> strongest(channel_posture(Ch), Acc) end,
                plaintext, Channels);
client_tls_posture(_) ->
    plaintext.

%% @doc True if any grpcbox client channel has an `https` endpoint (verified or
%% not). Pure; exported for testing.
-spec client_has_https(term()) -> boolean().
client_has_https(Client) -> client_tls_posture(Client) =/= plaintext.

-spec channel_posture(term()) -> tls_posture().
channel_posture({_Name, Endpoints, _Opts}) when is_list(Endpoints) ->
    lists:foldl(fun(E, Acc) -> strongest(endpoint_posture(E), Acc) end,
                plaintext, Endpoints);
channel_posture(_) ->
    plaintext.

-spec endpoint_posture(term()) -> tls_posture().
endpoint_posture(E) when is_tuple(E), tuple_size(E) >= 4, element(1, E) =:= https ->
    SslOpts = element(4, E),
    case is_list(SslOpts) andalso proplists:get_value(verify, SslOpts) =:= verify_peer of
        true  -> verified;
        false -> unverified
    end;
endpoint_posture(_) ->
    plaintext.

-spec strongest(tls_posture(), tls_posture()) -> tls_posture().
strongest(verified, _)            -> verified;
strongest(_, verified)            -> verified;
strongest(unverified, _)          -> unverified;
strongest(_, unverified)          -> unverified;
strongest(plaintext, plaintext)   -> plaintext.

%% @doc True if any grpcbox server (listener) carries TLS transport_opts
%% (`ssl => true`). Pure; exported for testing.
-spec servers_have_tls(term()) -> boolean().
servers_have_tls(Servers) when is_list(Servers) ->
    lists:any(fun(S) when is_map(S) ->
                      case maps:get(transport_opts, S, #{}) of
                          #{ssl := true} -> true;
                          _ -> false
                      end;
                 (_) -> false
              end, Servers);
servers_have_tls(_) ->
    false.
