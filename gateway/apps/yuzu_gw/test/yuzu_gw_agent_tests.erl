%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_agent — gen_statem lifecycle.
%%%
%%% Mocks: yuzu_gw_upstream, telemetry.
%%% Real:  yuzu_gw_registry (needs pg + ETS).
%%%
%%% The agent sends {send_command, Cmd} to its stream_pid (the test
%%% process). Responses from the agent arrive as {stream_data, Frame}.
%%% Stream close is signalled as the atom stream_closed.
%%%
%%% Key assertions:
%%%   - Agent transitions connecting → streaming on stream_ready
%%%   - Agent dispatches commands to stream_pid
%%%   - Agent tracks pending command map
%%%   - Agent cleans up and STOPS on stream close
%%%   - Pending command waiters are notified on disconnect
%%%   - Orphaned responses are silently dropped
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

agent_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"starts in streaming when stream_pid provided", fun starts_streaming/0},
      {"starts in connecting when stream_pid is undefined", fun starts_connecting/0},
      {"connecting transitions to streaming on stream_ready", fun connecting_to_streaming/0},
      {"connecting rejects dispatch", fun connecting_rejects_dispatch/0},
      {"streaming dispatches command to stream_pid", fun streaming_dispatches/0},
      {"streaming tracks pending commands", fun streaming_tracks_pending/0},
      {"streaming removes pending on terminal response", fun streaming_clears_pending/0},
      {"streaming keeps pending on RUNNING response", fun streaming_keeps_running/0},
      {"streaming handles orphaned response", fun streaming_orphaned_response/0},
      {"agent stops on stream_closed", fun stops_on_close/0},
      {"agent stops on stream_error", fun stops_on_error/0},
      {"disconnect notifies pending waiters", fun disconnect_notifies_pending/0},
      {"get_info returns state", fun get_info_works/0}
     ]}.

setup() ->
    %% Start pg and registry (real).
    case whereis(yuzu_gw) of
        undefined -> pg:start_link(yuzu_gw);
        _ -> ok
    end,
    case whereis(yuzu_gw_registry) of
        undefined -> {ok, _} = yuzu_gw_registry:start_link();
        _ -> ok
    end,
    %% Mock external deps.
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status,
                fun(_, _, _, _) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

cleanup(_) ->
    meck:unload([yuzu_gw_upstream, telemetry]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

starts_streaming() ->
    %% self() as stream_pid → starts in streaming state
    {Pid, _} = start_agent(<<"ss-1">>, self()),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(streaming, maps:get(state, Info)),
    stop_agent(Pid).

starts_connecting() ->
    %% undefined stream_pid → starts in connecting state
    {Pid, _} = start_agent(<<"sc-1">>, undefined),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(connecting, maps:get(state, Info)),
    stop_agent(Pid).

connecting_to_streaming() ->
    {Pid, _} = start_agent(<<"cts-1">>, undefined),
    {ok, Info1} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(connecting, maps:get(state, Info1)),
    %% stream_ready transitions to streaming.
    gen_statem:cast(Pid, {stream_ready, self()}),
    timer:sleep(20),
    {ok, Info2} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(streaming, maps:get(state, Info2)),
    stop_agent(Pid).

connecting_rejects_dispatch() ->
    {Pid, AgentId} = start_agent(<<"cr-1">>, undefined),
    Ref = make_ref(),
    yuzu_gw_agent:dispatch(Pid, #{command_id => <<"c1">>}, {self(), Ref}),
    receive
        {command_error, Ref, AgentId, not_connected} -> ok
    after 1000 ->
        ?assert(false, "Expected command_error not_connected")
    end,
    stop_agent(Pid).

streaming_dispatches() ->
    %% The agent sends {send_command, Cmd} to our process (stream_pid = self()).
    {Pid, _} = start_agent(<<"sd-1">>, self()),
    Ref = make_ref(),
    Cmd = #{command_id => <<"cmd-1">>, plugin => <<"svc">>, action => <<"list">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), Ref}),
    receive
        {send_command, ReceivedCmd} ->
            ?assertEqual(<<"cmd-1">>, maps:get(command_id, ReceivedCmd,
                                               maps:get(<<"command_id">>, ReceivedCmd, undefined)))
    after 1000 ->
        ?assert(false, "Expected {send_command, Cmd} from agent")
    end,
    stop_agent(Pid).

streaming_tracks_pending() ->
    {Pid, _} = start_agent(<<"stp-1">>, self()),
    Ref = make_ref(),
    Cmd = #{command_id => <<"cmd-p1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), Ref}),
    %% Drain the send_command message so our mailbox doesn't accumulate.
    receive {send_command, _} -> ok after 1000 -> ok end,
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(1, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_clears_pending() ->
    {Pid, _} = start_agent(<<"scp-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-c1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    %% Simulate terminal response arriving at the agent process.
    Pid ! {stream_data, #{command_id => <<"cmd-c1">>, status => 'SUCCESS'}},
    receive
        {command_response, FanoutRef, _, _} -> ok
    after 1000 ->
        ?assert(false, "Expected command_response")
    end,
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(0, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_keeps_running() ->
    {Pid, _} = start_agent(<<"skr-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-r1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    %% RUNNING status should NOT clear pending.
    Pid ! {stream_data, #{command_id => <<"cmd-r1">>, status => 'RUNNING'}},
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(1, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_orphaned_response() ->
    {Pid, _} = start_agent(<<"sor-1">>, self()),
    %% Send response for a command we never dispatched — should not crash.
    Pid ! {stream_data, #{command_id => <<"no-such-cmd">>, status => 'SUCCESS'}},
    timer:sleep(20),
    ?assert(is_process_alive(Pid)),
    stop_agent(Pid).

stops_on_close() ->
    {Pid, AgentId} = start_agent(<<"soc-1">>, self()),
    ?assert(is_process_alive(Pid)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(AgentId)),
    %% Simulate gRPC stream close.
    Pid ! stream_closed,
    ok = wait_for_death(Pid, 2000),
    %% Registry must be cleaned up.
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

stops_on_error() ->
    {Pid, AgentId} = start_agent(<<"soe-1">>, self()),
    Pid ! {stream_error, some_error},
    ok = wait_for_death(Pid, 2000),
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

disconnect_notifies_pending() ->
    {Pid, _AgentId} = start_agent(<<"dnp-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-d1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    timer:sleep(20),
    %% Disconnect the agent.
    Pid ! stream_closed,
    %% We should receive a command_error for the pending command.
    receive
        {command_error, FanoutRef, <<"dnp-1">>, agent_disconnected} -> ok
    after 2000 ->
        ?assert(false, "Expected command_error agent_disconnected")
    end.

get_info_works() ->
    {Pid, _} = start_agent(<<"gi-1">>, self()),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(<<"gi-1">>, maps:get(agent_id, Info)),
    ?assertEqual(streaming, maps:get(state, Info)),
    ?assert(is_integer(maps:get(connected_at, Info))),
    stop_agent(Pid).

%%%===================================================================
%%% Helpers
%%%===================================================================

start_agent(AgentId, StreamPid) ->
    Args = #{agent_id   => AgentId,
             session_id => <<"sess-", AgentId/binary>>,
             stream_pid => StreamPid,
             agent_info => #{plugins => [#{name => <<"svc">>}]},
             peer_addr  => <<"127.0.0.1">>},
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    {Pid, AgentId}.

stop_agent(Pid) ->
    case is_process_alive(Pid) of
        true ->
            yuzu_gw_agent:disconnect(Pid),
            wait_for_death(Pid, 2000);
        false ->
            ok
    end.

wait_for_death(Pid, Timeout) ->
    MonRef = monitor(process, Pid),
    receive
        {'DOWN', MonRef, process, Pid, _} -> ok
    after Timeout ->
        demonitor(MonRef, [flush]),
        ?assert(false, {process_still_alive, Pid})
    end.
