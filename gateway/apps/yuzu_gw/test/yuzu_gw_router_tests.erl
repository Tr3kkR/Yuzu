%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_router — command fanout coordinator.
%%%
%%% Uses real registry with fake agent processes to test fanout
%%% dispatch, completion tracking, timeout handling, and the
%%% skipped-agent path.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_router_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

router_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"fanout to single agent", fun fanout_single/0},
      {"fanout to multiple agents", fun fanout_multi/0},
      {"broadcast to all agents", fun fanout_broadcast/0},
      {"skipped agents send error immediately", fun fanout_skipped/0},
      {"all agents missing completes immediately", fun fanout_all_missing/0},
      {"timeout fires when agents don't respond", fun fanout_timeout/0},
      {"completion fires when all respond", fun fanout_all_respond/0}
     ]}.

setup() ->
    case whereis(yuzu_gw) of
        undefined -> pg:start_link(yuzu_gw);
        _ -> ok
    end,
    case whereis(yuzu_gw_registry) of
        undefined -> {ok, _} = yuzu_gw_registry:start_link();
        _ -> ok
    end,
    %% Mock telemetry to no-op.
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    {ok, RouterPid} = yuzu_gw_router:start_link(),
    RouterPid.

cleanup(RouterPid) ->
    meck:unload(telemetry),
    unlink(RouterPid),
    exit(RouterPid, shutdown),
    timer:sleep(50).

%%%===================================================================
%%% Tests
%%%===================================================================

fanout_single() ->
    {AgentPid, AgentId} = register_fake_agent(<<"fs-1">>),
    Cmd = #{command_id => <<"cmd-fs1">>, plugin => <<"svc">>},
    {ok, _FanoutRef} = yuzu_gw_router:send_command([AgentId], Cmd, #{}),
    %% The fake agent should receive the dispatch.
    receive
        {dispatch_received, <<"cmd-fs1">>} -> ok
    after 1000 ->
        ?assert(false, "Fake agent didn't receive dispatch")
    end,
    kill_fake(AgentPid).

fanout_multi() ->
    Agents = [register_fake_agent(iolist_to_binary(io_lib:format("fm-~b", [I])))
              || I <- lists:seq(1, 5)],
    Ids = [Id || {_, Id} <- Agents],
    Cmd = #{command_id => <<"cmd-fm">>, plugin => <<"svc">>},
    {ok, _FanoutRef} = yuzu_gw_router:send_command(Ids, Cmd, #{}),
    %% All 5 fake agents should get the dispatch.
    Received = collect_dispatches(5, 2000),
    ?assertEqual(5, length(Received)),
    lists:foreach(fun({Pid, _}) -> kill_fake(Pid) end, Agents).

fanout_broadcast() ->
    %% Register agents, then broadcast (empty ID list = all).
    Agents = [register_fake_agent(iolist_to_binary(io_lib:format("fb-~b", [I])))
              || I <- lists:seq(1, 3)],
    Cmd = #{command_id => <<"cmd-fb">>, plugin => <<"svc">>},
    {ok, _FanoutRef} = yuzu_gw_router:send_command([], Cmd, #{}),
    %% Broadcast targets all registered agents — at least our 3.
    Received = collect_dispatches(3, 2000),
    ?assert(length(Received) >= 3),
    lists:foreach(fun({Pid, _}) -> kill_fake(Pid) end, Agents).

fanout_skipped() ->
    %% Target an agent that doesn't exist.
    Cmd = #{command_id => <<"cmd-skip">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command(
        [<<"nonexistent-agent">>], Cmd, #{}),
    %% Should get immediate error + fanout_complete with 0 dispatched.
    receive
        {command_error, FanoutRef, <<"nonexistent-agent">>, not_connected} -> ok
    after 1000 ->
        ?assert(false, "Expected command_error for missing agent")
    end,
    receive
        {fanout_complete, FanoutRef, #{targets := 0, skipped := 1}} -> ok
    after 1000 ->
        ?assert(false, "Expected fanout_complete")
    end.

fanout_all_missing() ->
    Cmd = #{command_id => <<"cmd-am">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command(
        [<<"miss-1">>, <<"miss-2">>], Cmd, #{}),
    receive
        {fanout_complete, FanoutRef, #{targets := 0, skipped := 2}} -> ok
    after 1000 ->
        ?assert(false, "Expected immediate fanout_complete")
    end.

fanout_timeout() ->
    %% Register a fake agent that never responds.
    {AgentPid, AgentId} = register_fake_agent(<<"ft-1">>),
    Cmd = #{command_id => <<"cmd-ft">>, plugin => <<"svc">>},
    %% Use a very short timeout (1 second).
    {ok, FanoutRef} = yuzu_gw_router:send_command(
        [AgentId], Cmd, #{timeout_seconds => 1}),
    %% Wait for the timeout.
    receive
        {fanout_complete, FanoutRef, #{timed_out := 1}} -> ok
    after 3000 ->
        ?assert(false, "Expected fanout_complete with timed_out")
    end,
    kill_fake(AgentPid).

fanout_all_respond() ->
    Agents = [register_fake_agent(iolist_to_binary(io_lib:format("far-~b", [I])))
              || I <- lists:seq(1, 3)],
    Ids = [Id || {_, Id} <- Agents],
    Cmd = #{command_id => <<"cmd-far">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command(Ids, Cmd, #{}),
    %% Collect dispatches and have each fake agent send a terminal response.
    _Dispatches = collect_dispatches(3, 2000),
    %% Simulate terminal responses arriving at the router.
    lists:foreach(fun(Id) ->
        yuzu_gw_router ! {fanout_terminal, FanoutRef, Id}
    end, Ids),
    %% Should get fanout_complete with all received.
    receive
        {fanout_complete, FanoutRef, #{targets := 3, received := 3, timed_out := 0}} -> ok
    after 2000 ->
        ?assert(false, "Expected fanout_complete with all received")
    end,
    lists:foreach(fun({Pid, _}) -> kill_fake(Pid) end, Agents).

%%%===================================================================
%%% Fake agent process
%%%
%%% Mimics just enough of yuzu_gw_agent to be dispatched to by the
%%% router. Receives cast messages and notifies the test process.
%%%===================================================================

register_fake_agent(AgentId) ->
    TestPid = self(),
    Pid = spawn_link(fun() -> fake_agent_loop(TestPid) end),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid, <<"s">>, [<<"svc">>]),
    {Pid, AgentId}.

fake_agent_loop(TestPid) ->
    receive
        {'$gen_cast', {dispatch, CommandReq, {_ReplyTo, _FanoutRef}}} ->
            CmdId = maps:get(command_id, CommandReq,
                             maps:get(<<"command_id">>, CommandReq, undefined)),
            TestPid ! {dispatch_received, CmdId},
            fake_agent_loop(TestPid);
        stop ->
            ok;
        _ ->
            fake_agent_loop(TestPid)
    end.

kill_fake(Pid) ->
    Pid ! stop.

collect_dispatches(N, Timeout) ->
    collect_dispatches(N, Timeout, []).

collect_dispatches(0, _Timeout, Acc) -> lists:reverse(Acc);
collect_dispatches(N, Timeout, Acc) ->
    receive
        {dispatch_received, CmdId} ->
            collect_dispatches(N - 1, Timeout, [CmdId | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.
