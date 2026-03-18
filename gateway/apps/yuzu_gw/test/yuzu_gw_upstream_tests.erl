%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_upstream — heartbeat batching and proxying.
%%%
%%% Mocks grpcbox_client to test batching logic in isolation, without
%%% a real upstream server.
%%%
%%% Key assertions:
%%%   - Heartbeats accumulate in buffer between flushes
%%%   - Flush sends BatchHeartbeat with all buffered heartbeats
%%%   - Buffer is cleared after flush
%%%   - Empty buffer flush is a no-op (no RPC call)
%%%   - proxy_register returns upstream response
%%%   - proxy_inventory returns upstream response
%%%   - notify_stream_status is fire-and-forget (no crash on error)
%%%   - Buffer is retained on flush failure (not silently discarded)
%%%   - Buffer retention is capped to prevent unbounded growth
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

upstream_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"heartbeats are batched", fun heartbeats_batched/0},
      {"flush sends all buffered heartbeats", fun flush_sends_batch/0},
      {"empty flush sends no rpc", fun empty_flush_no_rpc/0},
      {"proxy_register returns response", fun proxy_register_ok/0},
      {"proxy_register returns error", fun proxy_register_error/0},
      {"proxy_inventory returns response", fun proxy_inventory_ok/0},
      {"notify_stream_status does not crash on error", fun notify_no_crash/0},
      {"buffer retained on flush failure", fun buffer_retained_on_failure/0},
      {"buffer cap prevents unbounded growth", fun buffer_cap_on_failure/0}
     ]}.

setup() ->
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% Use a long interval so flushes don't happen automatically during tests.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 600000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 5),
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    Pid.

cleanup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    timer:sleep(50),
    meck:unload([grpcbox_client, telemetry]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

heartbeats_batched() ->
    %% Queue several heartbeats.
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"s1">>}),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"s2">>}),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"s3">>}),
    %% No RPC should have been called yet (interval is 10 minutes).
    timer:sleep(50),
    %% The unary mock records calls. Check that BatchHeartbeat was NOT called.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [C || {_, {grpcbox_client, unary, [_, Path, _, _, _]}, _} = C <- Calls,
                       binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assertEqual(0, length(BatchCalls)).

flush_sends_batch() ->
    %% Flush any stale heartbeats from prior tests.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(50),
    %% Now reset and set up the real assertion mock.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),
    %% Queue exactly 2 heartbeats.
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"f1">>}),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"f2">>}),
    timer:sleep(20),
    %% Trigger flush manually.
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(100),
    %% Check that BatchHeartbeat was called with exactly 2 heartbeats.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assertEqual(2, length(HBs)).

empty_flush_no_rpc() ->
    meck:reset(grpcbox_client),
    %% Flush with empty buffer — just reschedules the timer.
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(50),
    %% No RPC calls should have been made.
    Calls = meck:history(grpcbox_client),
    ?assertEqual(0, length(Calls)).

proxy_register_ok() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {ok, #{session_id => <<"new-sess">>}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"a1">>}}),
    ?assertMatch({ok, #{session_id := <<"new-sess">>}}, Result).

proxy_register_error() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {error, {14, <<"UNAVAILABLE">>, #{}}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertMatch({error, {14, _}}, Result).

proxy_inventory_ok() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyInventory">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {ok, #{received => true}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_inventory(#{session_id => <<"s1">>}),
    ?assertMatch({ok, #{received := true}}, Result).

notify_no_crash() ->
    %% Make the notify RPC fail — should not crash the upstream process.
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"NotifyStreamStatus">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {error, connection_refused}
        end
    end),
    yuzu_gw_upstream:notify_stream_status(<<"a1">>, <<"s1">>, connected, <<"127.0.0.1">>),
    timer:sleep(100),
    %% The upstream process should still be alive.
    ?assert(is_process_alive(whereis(yuzu_gw_upstream))).

buffer_retained_on_failure() ->
    %% First drain any existing buffer.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(50),
    meck:reset(grpcbox_client),

    %% Queue 3 heartbeats.
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"r1">>}),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"r2">>}),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"r3">>}),
    timer:sleep(20),

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(100),

    %% Now make flush succeed and add one more heartbeat.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),
    yuzu_gw_upstream:queue_heartbeat(#{session_id => <<"r4">>}),
    timer:sleep(20),

    %% Trigger flush — should include all 4 heartbeats (3 retained + 1 new).
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(100),

    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assertEqual(4, length(HBs)).

buffer_cap_on_failure() ->
    %% Max buffer is set to 5 in setup. First drain any existing buffer.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(50),
    meck:reset(grpcbox_client),

    %% Queue 10 heartbeats (exceeds cap of 5).
    lists:foreach(fun(I) ->
        yuzu_gw_upstream:queue_heartbeat(#{session_id => integer_to_binary(I)})
    end, lists:seq(1, 10)),
    timer:sleep(20),

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(100),

    %% Now make flush succeed.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),

    %% Trigger flush — should include at most 5 (capped) heartbeats.
    whereis(yuzu_gw_upstream) ! flush_heartbeats,
    timer:sleep(100),

    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assert(length(HBs) =< 5).
