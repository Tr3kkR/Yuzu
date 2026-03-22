%%%-------------------------------------------------------------------
%%% @doc Non-functional EUnit tests for C2: health endpoint
%%% degraded-state behaviour, concurrent access, and response time.
%%%
%%% Covers:
%%%   - readyz returns 503 when a core process is dead
%%%   - readyz returns 503 when circuit breaker is open
%%%   - Health endpoint handles concurrent requests without errors
%%%   - Health endpoint responds within bounded time
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_health_nf_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

health_nf_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     {timeout, 30,
      [
       {"readyz 503 when registry process is dead",
        fun readyz_503_dead_process/0},
       {"readyz 503 when circuit breaker is open",
        fun readyz_503_circuit_open/0},
       {"concurrent health checks complete without error",
        fun concurrent_health_checks/0},
       {"healthz response time is bounded",
        fun healthz_response_time/0},
       {"readyz response time is bounded",
        fun readyz_response_time/0}
      ]}}.

setup() ->
    Port = 18081,
    application:set_env(yuzu_gw, health_port, Port),

    %% Trap exits for the group process. With {setup, ...}, the group
    %% process stays alive while tests run in sub-processes. The upstream
    %% and health gen_servers are start_link-ed to this process. If we
    %% disable trap_exit and a linked gen_server dies (e.g. test kills
    %% registry, readyz returns 503, etc.), the EXIT signal cascades to
    %% the group process, killing it and cancelling all tests (::killed).
    %% Keep trap_exit = true for the entire lifetime of the group process.
    process_flag(trap_exit, true),

    %% Synchronously kill stale gen_servers from prior test suites.
    %% Use monitors to wait for actual death — never timer:sleep.
    sync_kill(yuzu_gw_health),
    sync_kill(yuzu_gw_upstream),
    drain_exits(),

    %% Start mock processes for readiness checks (spawn, NOT spawn_link).
    MockNames = [yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_router],
    MockPids = lists:filtermap(fun(Name) ->
        case whereis(Name) of
            undefined ->
                Pid = spawn(fun() -> mock_loop() end),
                register(Name, Pid),
                {true, {Name, Pid, true}};
            _Existing ->
                {true, {Name, undefined, false}}
        end
    end, MockNames),

    %% Safely set up meck — unload first if already mocked by a prior suite.
    safe_meck_new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    safe_meck_new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 200),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),

    %% Start the health endpoint.
    {ok, HealthPid} = yuzu_gw_health:start_link(),
    timer:sleep(100),
    {Port, HealthPid, UpPid, MockPids}.

cleanup({_Port, HealthPid, UpPid, MockPids}) ->
    process_flag(trap_exit, true),
    %% Synchronous shutdown — wait for actual death via monitors.
    sync_stop(HealthPid),
    sync_stop(UpPid),
    lists:foreach(fun
        ({Name, Pid, true}) ->
            catch unregister(Name),
            catch exit(Pid, kill);
        ({_Name, _Pid, false}) ->
            ok
    end, MockPids),
    drain_exits(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    process_flag(trap_exit, false),
    ok.

mock_loop() ->
    receive
        stop -> ok;
        _ -> mock_loop()
    after 60000 -> ok
    end.

%%%===================================================================
%%% Process lifecycle helpers
%%%===================================================================

%% @doc Synchronously kill a registered process and wait for it to die.
%% Uses a monitor to get a 'DOWN' message — no timer:sleep guessing.
sync_kill(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            Ref = monitor(process, Pid),
            catch unlink(Pid),
            catch exit(Pid, kill),
            receive
                {'DOWN', Ref, process, Pid, _} -> ok
            after 5000 ->
                demonitor(Ref, [flush])
            end
    end.

%% @doc Synchronously stop a process by pid and wait for death.
sync_stop(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        false -> ok;
        true ->
            Ref = monitor(process, Pid),
            catch unlink(Pid),
            catch exit(Pid, shutdown),
            receive
                {'DOWN', Ref, process, Pid, _} -> ok
            after 5000 ->
                catch exit(Pid, kill),
                receive
                    {'DOWN', Ref, process, Pid, _} -> ok
                after 1000 ->
                    demonitor(Ref, [flush])
                end
            end
    end;
sync_stop(_) -> ok.

%% @doc Safely create a meck mock, unloading first if already mocked.
safe_meck_new(Mod, Opts) ->
    try meck:new(Mod, Opts)
    catch _:_ ->
        catch meck:unload(Mod),
        meck:new(Mod, Opts)
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

readyz_503_dead_process() ->
    %% Kill the registry mock to simulate a dead core process.
    %% Must trap exits to avoid cascading death to the test process.
    process_flag(trap_exit, true),
    case whereis(yuzu_gw_registry) of
        undefined ->
            ok;  % already absent — readyz will see it as down
        Pid ->
            catch unlink(Pid),
            catch unregister(yuzu_gw_registry),
            catch exit(Pid, kill),
            timer:sleep(50)
    end,
    drain_exits(),
    {Status, Body} = http_get(18081, "/readyz"),
    ?assertEqual(503, Status),
    ?assert(binary:match(Body, <<"not_ready">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"registry\":false">>) =/= nomatch),
    %% Re-register a mock so cleanup and subsequent tests don't fail.
    NewPid = spawn(fun() -> mock_loop() end),
    register(yuzu_gw_registry, NewPid),
    process_flag(trap_exit, false).

readyz_503_circuit_open() ->
    %% Trip the circuit breaker to open state.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% readyz should now return 503.
    {Status, Body} = http_get(18081, "/readyz"),
    ?assertEqual(503, Status),
    ?assert(binary:match(Body, <<"not_ready">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"circuit_breaker\":false">>) =/= nomatch),

    %% Restore the circuit to closed for other tests.
    %% Wait for half_open, then succeed a probe.
    timer:sleep(350),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"recovered">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

concurrent_health_checks() ->
    %% Fire 50 concurrent healthz requests and verify all succeed.
    Self = self(),
    N = 50,
    Workers = [spawn_link(fun() ->
        Result = http_get(18081, "/healthz"),
        Self ! {health_result, I, Result}
    end) || I <- lists:seq(1, N)],

    Results = [receive
        {health_result, I, R} -> R
    after 10000 ->
        {0, <<"timeout">>}
    end || I <- lists:seq(1, N)],

    %% All should be 200.
    Statuses = [S || {S, _} <- Results],
    TwoHundreds = length([S || S <- Statuses, S =:= 200]),
    ?assertEqual(N, TwoHundreds),
    %% Workers are linked, will be cleaned up.
    _ = Workers.

healthz_response_time() ->
    %% Measure 20 sequential healthz requests. Average should be < 10ms.
    Timings = [begin
        T0 = erlang:monotonic_time(microsecond),
        {200, _} = http_get(18081, "/healthz"),
        T1 = erlang:monotonic_time(microsecond),
        T1 - T0
    end || _ <- lists:seq(1, 20)],
    AvgUs = lists:sum(Timings) / length(Timings),
    %% Average should be well under 10ms (10000 us).
    ?assert(AvgUs < 10000).

readyz_response_time() ->
    %% readyz does process checks + circuit breaker query. Should still be fast.
    Timings = [begin
        T0 = erlang:monotonic_time(microsecond),
        {200, _} = http_get(18081, "/readyz"),
        T1 = erlang:monotonic_time(microsecond),
        T1 - T0
    end || _ <- lists:seq(1, 20)],
    AvgUs = lists:sum(Timings) / length(Timings),
    %% Average should be under 20ms (20000 us) — includes gen_server call.
    ?assert(AvgUs < 20000).

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

drain_exits() ->
    receive {'EXIT', _, _} -> drain_exits()
    after 0 -> ok
    end.
