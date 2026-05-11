%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the HTTP health/readiness endpoint.
%%%
%%% Tests /healthz (liveness), /readyz (readiness), and 404 for
%%% unknown paths.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_health_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

health_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"healthz returns 200", fun healthz_ok/0},
      {"readyz returns 200 when core processes alive", fun readyz_ok/0},
      {"unknown path returns 404", fun unknown_path_404/0}
     ]}.

%% Canonical grpcbox listener configs that match sys.config. Tests register
%% mock pids under `grpcbox_services_sup:services_sup_name/1` of each so the
%% #896 readyz probe finds them registered. Helpers match the
%% `yuzu_gw_health_nf_tests` pattern (qe SHOULD-4) so a future grpcbox API
%% change is a single-place update across both suites.
agent_listen_opts() -> #{port => 50051, ip => {0,0,0,0}}.
mgmt_listen_opts()  -> #{port => 50063, ip => {127,0,0,1}}.

setup() ->
    %% Bind to port 0 — the OS picks an ephemeral free port and we read
    %% it back from the started gen_server via yuzu_gw_health:port/0.
    %% A previous version of this test hardcoded port 18080, which is
    %% squatted on the Windows CI runner by an unidentified HTTP server
    %% that returns 302 Found for every request — making the eunit
    %% assertion `?assertEqual(200, Status)` fail with `value, 302`.
    %% Ephemeral binding eliminates that whole class of port collision.
    application:set_env(yuzu_gw, health_port, 0),

    %% Snapshot grpcbox.servers so cleanup can restore (UP-313 — see the
    %% same pattern in yuzu_gw_health_nf_tests).
    PriorGrpcboxServers = application:get_env(grpcbox, servers),
    application:set_env(grpcbox, servers, [
        #{listen_opts => agent_listen_opts()},
        #{listen_opts => mgmt_listen_opts()}
    ]),

    %% Start mock processes for readiness checks.
    %% Only register names that aren't already taken by other test suites.
    %% grpcbox supervisor atoms join the list — sys.config configures two
    %% servers (agent-facing 50051, mgmt-facing 50063) and the #896 readyz
    %% probe expects their supervisors registered. In eunit grpcbox itself
    %% is not started, so we register stand-in pids to satisfy the probe.
    MockNames = [
        yuzu_gw_registry,
        yuzu_gw_agent_sup,
        yuzu_gw_router,
        grpcbox_services_sup:services_sup_name(agent_listen_opts()),
        grpcbox_services_sup:services_sup_name(mgmt_listen_opts())
    ],
    %% Bare `spawn` (not `spawn_link`) — parity with yuzu_gw_health_nf_tests
    %% and avoidance of the #336 catchall-mock-loop foot-gun (gateway-erlang
    %% SHOULD-2). If a future caller does gen_server:call/2 against the
    %% registered name it'll silently match the catchall and hang for 5s.
    MockPids = lists:filtermap(fun(Name) ->
        case whereis(Name) of
            undefined ->
                Pid = spawn(fun() -> mock_loop() end),
                register(Name, Pid),
                {true, {Name, Pid, true}};  % true = we own it
            _Existing ->
                {true, {Name, undefined, false}}  % false = already registered
        end
    end, MockNames),

    %% Start upstream with mocked grpcbox for circuit_state/0
    NeedUpstream = (whereis(yuzu_gw_upstream) =:= undefined),
    UpPid = case NeedUpstream of
        true ->
            catch meck:unload(grpcbox_client),
            catch meck:unload(telemetry),
            meck:new(grpcbox_client, [non_strict, no_link]),
            meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
                {ok, #{}, #{}}
            end),
            meck:new(telemetry, [passthrough, no_link]),
            meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
            application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 5),
            application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 10000),
            application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 300000),
            {ok, P} = yuzu_gw_upstream:start_link(),
            P;
        false ->
            whereis(yuzu_gw_upstream)
    end,

    %% Start the health endpoint, then read back the actual ephemeral
    %% port the OS assigned. The 100ms sleep keeps the original timing
    %% margin so the listener's accept loop is up before any test fires.
    {ok, HealthPid} = yuzu_gw_health:start_link(),
    timer:sleep(100),
    {ok, Port} = yuzu_gw_health:port(),
    {Port, HealthPid, UpPid, NeedUpstream, MockPids, PriorGrpcboxServers}.

cleanup({_Port, HealthPid, UpPid, NeedUpstream, MockPids, PriorGrpcboxServers}) ->
    catch unlink(HealthPid),
    catch exit(HealthPid, shutdown),
    case NeedUpstream of
        true ->
            catch unlink(UpPid),
            catch exit(UpPid, shutdown),
            meck:unload([grpcbox_client, telemetry]);
        false ->
            ok
    end,
    lists:foreach(fun
        ({Name, Pid, true}) ->
            catch unregister(Name),
            catch unlink(Pid),
            catch exit(Pid, kill);
        ({_Name, _Pid, false}) ->
            ok
    end, MockPids),
    %% UP-313 restore — see nf_tests for the rationale.
    case PriorGrpcboxServers of
        undefined -> application:unset_env(grpcbox, servers);
        {ok, V}   -> application:set_env(grpcbox, servers, V)
    end,
    timer:sleep(50),
    ok.

mock_loop() ->
    %% Tagged-match clauses only — refuses to swallow `gen_server:call/2`
    %% style messages so a leaked registration that gets accidentally
    %% probed by gen_server fails loud (gateway-erlang SHOULD-2 / #336).
    receive
        stop -> ok
    after 60000 -> ok
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

%% setup() bound the listener on port 0 (OS-assigned). Each test reads
%% the actual port from the running gen_server. Eunit's `{setup, …, [Tests]}`
%% form does not pass the setup return value to the tests, so the indirection
%% via yuzu_gw_health:port/0 is the cheapest way to thread the port through.
healthz_ok() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, Body} = http_get(Port, "/healthz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ok">>) =/= nomatch).

readyz_ok() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, Body} = http_get(Port, "/readyz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ready">>) =/= nomatch),
    %% Core checks should be true.
    ?assert(binary:match(Body, <<"\"registry\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"upstream\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"circuit_breaker\":true">>) =/= nomatch),
    %% #896 transport listeners should also be present (happy-path SHOULD-1) —
    %% the suite registers grpcbox supervisor mocks under both listener atoms,
    %% so the readyz check finds them and emits role-named keys.
    ?assert(binary:match(Body, <<"\"agent_listener\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"mgmt_listener\":true">>) =/= nomatch).

unknown_path_404() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, _Body} = http_get(Port, "/unknown"),
    ?assertEqual(404, Status).

%%%===================================================================
%%% HTTP client helper (minimal, no deps)
%%%===================================================================

http_get(Port, Path) ->
    {ok, Sock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
    Req = iolist_to_binary([
        "GET ", Path, " HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close\r\n",
        "\r\n"
    ]),
    ok = gen_tcp:send(Sock, Req),
    {ok, Data} = recv_all(Sock, <<>>),
    gen_tcp:close(Sock),
    parse_response(Data).

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Chunk}    -> recv_all(Sock, <<Acc/binary, Chunk/binary>>);
        {error, closed} -> {ok, Acc};
        {error, _} = Err -> Err
    end.

parse_response(Data) ->
    case binary:split(Data, <<"\r\n">>) of
        [StatusLine, Rest] ->
            Status = parse_status(StatusLine),
            Body = case binary:split(Rest, <<"\r\n\r\n">>) of
                [_Headers, B] -> B;
                _             -> <<>>
            end,
            {Status, Body};
        _ ->
            {0, <<>>}
    end.

parse_status(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [_, Code | _] -> binary_to_integer(Code);
        _             -> 0
    end.
