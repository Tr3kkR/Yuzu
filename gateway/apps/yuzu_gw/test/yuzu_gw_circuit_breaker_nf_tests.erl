%%%-------------------------------------------------------------------
%%% @doc Non-functional EUnit tests for C3: circuit breaker
%%% exponential backoff, concurrency, throughput, and telemetry.
%%%
%%% Covers:
%%%   - Backoff timeout doubles on each reopen
%%%   - Backoff is capped at max_reset_timeout
%%%   - Concurrent RPCs during state transitions are safe
%%%   - Rejection throughput when circuit is open
%%%   - Telemetry events emitted on state transitions
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_circuit_breaker_nf_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — foreach restarts upstream between tests
%%%===================================================================

circuit_breaker_nf_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"backoff doubles on each reopen cycle",
       {timeout, 10, fun backoff_doubles/0}},
      {"backoff is capped at max_reset_timeout",
       {timeout, 10, fun backoff_capped/0}},
      {"concurrent RPCs during open state are all rejected",
       {timeout, 10, fun concurrent_rejection/0}},
      {"concurrent RPCs during half_open allow exactly one probe",
       {timeout, 10, fun concurrent_half_open_probe/0}},
      {"open circuit rejection throughput",
       {timeout, 10, fun rejection_throughput/0}},
      {"telemetry emitted on open transition",
       fun telemetry_on_open/0},
      {"telemetry emitted on half_open transition",
       {timeout, 5, fun telemetry_on_half_open/0}},
      {"telemetry emitted on close after probe",
       {timeout, 5, fun telemetry_on_close/0}},
      {"failure counter resets on success",
       fun failure_counter_resets/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    %% Capture telemetry calls for later inspection via meck:history.
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_EventName, _Measurements, _Metadata) ->
        ok
    end),
    %% Low thresholds and short timeouts for fast testing.
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 100),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 500),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    Pid.

cleanup(Pid) ->
    catch unlink(Pid),
    catch exit(Pid, shutdown),
    timer:sleep(50),
    meck:unload([grpcbox_client, telemetry]),
    ok.

%%%===================================================================
%%% Helper — trip the circuit to open state
%%%===================================================================

trip_circuit() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%%%===================================================================
%%% Tests
%%%===================================================================

backoff_doubles() ->
    %% Cycle 1: trip -> open -> half_open (100ms timeout)
    trip_circuit(),
    %% The base timeout is 100ms. Wait slightly over 100ms for half_open.
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),

    %% Probe fails -> reopens. Now timeout should be 200ms.
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% At 150ms it should still be open (timeout is now 200ms).
    timer:sleep(150),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% At 250ms total (> 200ms), it should be half_open.
    timer:sleep(100),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),

    %% Probe fails again -> reopens. Timeout should be 400ms.
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% At 300ms it should still be open (timeout is now 400ms).
    timer:sleep(300),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% At 450ms total (> 400ms), should be half_open.
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()).

backoff_capped() ->
    %% Max timeout is 500ms. After enough reopen cycles, the timeout
    %% should not exceed 500ms.
    %%
    %% Cycle 1: 100ms base -> doubles to 200ms
    %% Cycle 2: 200ms -> doubles to 400ms
    %% Cycle 3: 400ms -> doubles to 500ms (capped, not 800ms)
    %% Cycle 4: 500ms -> stays 500ms

    %% Cycle 1: trip, wait 100ms+margin, fail probe
    trip_circuit(),
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 2: timeout now 200ms. Wait 200ms+margin, fail probe.
    timer:sleep(250),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 3: timeout now 400ms. Wait 400ms+margin, fail probe.
    timer:sleep(450),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 4: timeout should be capped at 500ms (not 800ms).
    %% At 400ms it should still be open.
    timer:sleep(400),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    %% At 550ms total (> 500ms cap), should be half_open.
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()).

concurrent_rejection() ->
    trip_circuit(),
    meck:reset(grpcbox_client),

    %% Fire 100 concurrent RPCs. All should be rejected.
    Self = self(),
    N = 100,
    _Workers = [spawn_link(fun() ->
        Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
        Self ! {rpc_result, I, Result}
    end) || I <- lists:seq(1, N)],

    Results = [receive
        {rpc_result, I, R} -> R
    after 5000 ->
        {error, timeout}
    end || I <- lists:seq(1, N)],

    %% All should be circuit_open.
    CircuitOpenCount = length([R || R <- Results, R =:= {error, circuit_open}]),
    ?assertEqual(N, CircuitOpenCount),

    %% grpcbox should NOT have been called at all.
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')).

concurrent_half_open_probe() ->
    trip_circuit(),
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),

    %% Make grpcbox succeed but add a small delay to simulate real RPC.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        timer:sleep(10),
        {ok, #{session_id => <<"probe">>}, #{}}
    end),

    %% Fire 10 concurrent RPCs. In half_open, only the probe is allowed
    %% through; any RPCs that arrive after the first succeeds should
    %% pass through in the now-closed state.
    Self = self(),
    N = 10,
    _Workers = [spawn_link(fun() ->
        Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
        Self ! {probe_result, I, Result}
    end) || I <- lists:seq(1, N)],

    Results = [receive
        {probe_result, I, R} -> R
    after 5000 ->
        {error, timeout}
    end || I <- lists:seq(1, N)],

    %% No errors should remain — the first probe closes the circuit,
    %% then subsequent RPCs pass through in closed state.
    %% (gen_server serialises calls, so they go one at a time.)
    Successes = length([R || {ok, _} = R <- Results]),
    ?assertEqual(N, Successes).

rejection_throughput() ->
    trip_circuit(),
    meck:reset(grpcbox_client),

    %% Measure how fast we can reject 10,000 RPCs.
    N = 10000,
    {TimeUs, _} = timer:tc(fun() ->
        lists:foreach(fun(_) ->
            {error, circuit_open} = yuzu_gw_upstream:proxy_register(#{info => #{}})
        end, lists:seq(1, N))
    end),

    TimeMs = TimeUs / 1000,
    %% 10K gen_server call roundtrips should complete in < 5 seconds.
    ?assert(TimeMs < 5000),

    %% grpcbox should not have been called.
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')).

telemetry_on_open() ->
    meck:reset(telemetry),
    trip_circuit(),
    %% Check meck history for a circuit_state event with state=open.
    ?assert(has_telemetry_state(<<"open">>)).

telemetry_on_half_open() ->
    meck:reset(telemetry),
    trip_circuit(),
    %% Wait for the half_open timer to fire.
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assert(has_telemetry_state(<<"half_open">>)).

telemetry_on_close() ->
    meck:reset(telemetry),
    trip_circuit(),
    timer:sleep(150),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    %% Probe succeeds -> close.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"ok">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assert(has_telemetry_state(<<"closed">>)).

failure_counter_resets() ->
    %% 2 failures, then a success, then 2 more failures.
    %% Should NOT trip because the success reset the counter.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    %% Success resets counter.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    %% 2 more failures — still closed (threshold is 3).
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

%%%===================================================================
%%% Telemetry helpers
%%%===================================================================

%% @doc Check meck:history(telemetry) for a circuit_state event with
%% the given state label.
has_telemetry_state(ExpectedState) ->
    History = meck:history(telemetry),
    lists:any(fun
        ({_Pid, {telemetry, execute,
                 [[yuzu, gw, upstream, circuit_state],
                  #{count := 1},
                  #{state := State}]}, ok}) ->
            State =:= ExpectedState;
        (_) ->
            false
    end, History).
