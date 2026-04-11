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

setup() ->
    %% Use a high port to avoid conflicts
    Port = 18080,
    application:set_env(yuzu_gw, health_port, Port),

    %% Start mock processes for readiness checks.
    %% Only register names that aren't already taken by other test suites.
    MockNames = [yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_router],
    MockPids = lists:filtermap(fun(Name) ->
        case whereis(Name) of
            undefined ->
                Pid = spawn_link(fun() -> mock_loop() end),
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

    %% Start the health endpoint
    {ok, HealthPid} = yuzu_gw_health:start_link(),
    timer:sleep(100),
    {Port, HealthPid, UpPid, NeedUpstream, MockPids}.

cleanup({_Port, HealthPid, UpPid, NeedUpstream, MockPids}) ->
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
    timer:sleep(50),
    ok.

mock_loop() ->
    receive
        stop -> ok;
        _ -> mock_loop()
    after 60000 -> ok
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

healthz_ok() ->
    {Status, Body} = http_get(18080, "/healthz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ok">>) =/= nomatch).

readyz_ok() ->
    {Status, Body} = http_get(18080, "/readyz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ready">>) =/= nomatch),
    %% Core checks should be true
    ?assert(binary:match(Body, <<"\"registry\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"upstream\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"circuit_breaker\":true">>) =/= nomatch).

unknown_path_404() ->
    {Status, _Body} = http_get(18080, "/unknown"),
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
