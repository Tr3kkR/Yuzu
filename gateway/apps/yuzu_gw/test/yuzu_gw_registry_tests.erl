%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_registry — ETS routing table + pg groups.
%%%
%%% Tests registration, lookup, deregistration, process monitor cleanup,
%%% pg group membership, cursor-based pagination, pending registration
%%% storage (store_pending/take_pending), TTL sweep, and monitor ref
%%% leak prevention.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — start pg + registry, stop after
%%%===================================================================

registry_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"register and lookup", fun register_and_lookup/0},
      {"lookup missing returns error", fun lookup_missing/0},
      {"deregister removes entry", fun deregister_removes/0},
      {"monitor auto-cleans on process death", fun monitor_cleanup/0},
      {"re-register same agent_id replaces old", fun reregister_replaces/0},
      {"all_agents returns all ids", fun all_agents_list/0},
      {"agent_count is accurate", fun agent_count_accurate/0},
      {"pg group membership for plugins", fun pg_plugin_groups/0},
      {"pagination returns correct pages", fun pagination_basic/0},
      {"pagination cursor advances correctly", fun pagination_cursor/0},
      {"deregister non-existent is safe", fun deregister_nonexistent/0},
      {"lookup dead process returns error", fun lookup_dead_process/0},
      %% Pending registration tests
      {"store_pending and take_pending round-trip", fun pending_store_take/0},
      {"take_pending returns undefined for unknown session", fun pending_take_unknown/0},
      {"take_pending deletes entry atomically", fun pending_take_deletes/0},
      {"pending sweep removes expired entries", fun pending_sweep_expired/0},
      {"pending sweep preserves fresh entries", fun pending_sweep_preserves_fresh/0},
      %% Monitor ref leak test
      {"re-register does not leak monitor refs", fun reregister_no_monitor_leak/0}
     ]}.

setup() ->
    %% pg needs kernel to be started; it should be in test env.
    case whereis(yuzu_gw) of
        undefined -> pg:start_link(yuzu_gw);
        _         -> ok
    end,
    case yuzu_gw_registry:start_link() of
        {ok, Pid}                       -> Pid;
        {error, {already_started, Pid}} -> Pid
    end.

cleanup(_Pid) ->
    %% Don't stop the registry — other test suites share it.
    ok.

%%%===================================================================
%%% Correctness tests
%%%===================================================================

register_and_lookup() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-1">>, Pid, <<"sess-1">>, [<<"svc">>], <<>>),
    ?assertMatch({ok, Pid}, yuzu_gw_registry:lookup(<<"agent-1">>)),
    kill_dummy(Pid).

lookup_missing() ->
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"no-such-agent">>)).

deregister_removes() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-2">>, Pid, <<"s">>, [], <<>>),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(<<"agent-2">>)),
    yuzu_gw_registry:deregister_agent(<<"agent-2">>),
    timer:sleep(20),  %% cast is async
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"agent-2">>)),
    kill_dummy(Pid).

monitor_cleanup() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-3">>, Pid, <<"s">>, [], <<>>),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(<<"agent-3">>)),
    %% Kill the process — registry should auto-clean via DOWN monitor.
    kill_dummy(Pid),
    timer:sleep(50),
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"agent-3">>)).

reregister_replaces() ->
    Pid1 = spawn_dummy(),
    Pid2 = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-4">>, Pid1, <<"s1">>, [], <<>>),
    ok = yuzu_gw_registry:register_agent(<<"agent-4">>, Pid2, <<"s2">>, [], <<>>),
    ?assertMatch({ok, Pid2}, yuzu_gw_registry:lookup(<<"agent-4">>)),
    kill_dummy(Pid1),
    kill_dummy(Pid2).

all_agents_list() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 5)],
    Ids = [iolist_to_binary(io_lib:format("all-~b", [I])) || I <- lists:seq(1, 5)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    All = yuzu_gw_registry:all_agents(),
    lists:foreach(fun(Id) ->
        ?assert(lists:member(Id, All))
    end, Ids),
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

agent_count_accurate() ->
    InitialCount = yuzu_gw_registry:agent_count(),
    Pids = [spawn_dummy() || _ <- lists:seq(1, 10)],
    Ids = [iolist_to_binary(io_lib:format("count-~b", [I])) || I <- lists:seq(1, 10)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    ?assertEqual(InitialCount + 10, yuzu_gw_registry:agent_count()),
    %% Cleanup
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids),
    timer:sleep(100),
    ?assertEqual(InitialCount, yuzu_gw_registry:agent_count()).

pg_plugin_groups() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"pg-agent">>, Pid, <<"s">>, [<<"svc">>, <<"fs">>], <<>>),
    %% Agent should be in the plugin groups.
    SvcMembers = pg:get_members(yuzu_gw, {plugin, <<"svc">>}),
    FsMembers = pg:get_members(yuzu_gw, {plugin, <<"fs">>}),
    ?assert(lists:member(Pid, SvcMembers)),
    ?assert(lists:member(Pid, FsMembers)),
    kill_dummy(Pid).

pagination_basic() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 5)],
    Ids = [iolist_to_binary(io_lib:format("page-~2..0b", [I])) || I <- lists:seq(1, 5)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    %% Page size 3 should give 3 agents + a cursor.
    {Page1, Cursor1} = yuzu_gw_registry:list_agents(3, undefined),
    ?assertEqual(3, length(Page1)),
    ?assertNotEqual(undefined, Cursor1),
    %% Second page should give remaining.
    {Page2, _Cursor2} = yuzu_gw_registry:list_agents(3, Cursor1),
    %% Page2 should have at least the remaining agents (may include others from other tests).
    ?assert(length(Page2) >= 2),
    %% Cleanup
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

pagination_cursor() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 20)],
    Ids = [iolist_to_binary(io_lib:format("cur-~3..0b", [I])) || I <- lists:seq(1, 20)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    %% Walk all pages and collect agent IDs — every ID should appear exactly once.
    AllFound = collect_all_pages(7, undefined, []),
    lists:foreach(fun(Id) ->
        Matches = [A || #{agent_id := A} <- AllFound, A =:= Id],
        ?assertEqual(1, length(Matches), {missing_or_duplicate, Id})
    end, Ids),
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

deregister_nonexistent() ->
    %% Should not crash.
    yuzu_gw_registry:deregister_agent(<<"does-not-exist">>),
    timer:sleep(20),
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"does-not-exist">>)).

lookup_dead_process() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"dead-lookup">>, Pid, <<"s">>, [], <<>>),
    MonRef = monitor(process, Pid),
    kill_dummy(Pid),
    receive {'DOWN', MonRef, process, Pid, _} -> ok after 1000 -> error(timeout) end,
    %% Process is confirmed dead; lookup checks is_process_alive and should return error.
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"dead-lookup">>)).

%%%===================================================================
%%% Pending registration tests
%%%===================================================================

pending_store_take() ->
    Info = #{agent_id => <<"pending-1">>, peer_addr => <<"1.2.3.4">>},
    ok = yuzu_gw_registry:store_pending(<<"sess-pend-1">>, Info),
    Result = yuzu_gw_registry:take_pending(<<"sess-pend-1">>),
    ?assertEqual(Info, Result).

pending_take_unknown() ->
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"no-such-session">>)).

pending_take_deletes() ->
    Info = #{agent_id => <<"pending-2">>},
    ok = yuzu_gw_registry:store_pending(<<"sess-pend-2">>, Info),
    %% First take returns the data.
    ?assertEqual(Info, yuzu_gw_registry:take_pending(<<"sess-pend-2">>)),
    %% Second take returns undefined (already deleted).
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"sess-pend-2">>)).

pending_sweep_expired() ->
    %% Directly insert an expired entry into the ETS table.
    ExpiredTime = erlang:system_time(millisecond) - 200000,  %% 200s ago (TTL is 120s)
    ets:insert(yuzu_gw_pending, {<<"sweep-expired-1">>, #{agent_id => <<"x">>}, ExpiredTime}),

    %% Trigger sweep.
    yuzu_gw_registry ! sweep_pending,
    timer:sleep(50),

    %% Expired entry should be gone.
    ?assertEqual([], ets:lookup(yuzu_gw_pending, <<"sweep-expired-1">>)).

pending_sweep_preserves_fresh() ->
    %% Insert a fresh entry.
    FreshTime = erlang:system_time(millisecond),
    ets:insert(yuzu_gw_pending, {<<"sweep-fresh-1">>, #{agent_id => <<"y">>}, FreshTime}),

    %% Also insert an expired one.
    ExpiredTime = erlang:system_time(millisecond) - 200000,
    ets:insert(yuzu_gw_pending, {<<"sweep-expired-2">>, #{agent_id => <<"z">>}, ExpiredTime}),

    %% Trigger sweep.
    yuzu_gw_registry ! sweep_pending,
    timer:sleep(50),

    %% Fresh entry should still exist.
    ?assertMatch([{_, _, _}], ets:lookup(yuzu_gw_pending, <<"sweep-fresh-1">>)),
    %% Expired entry should be gone.
    ?assertEqual([], ets:lookup(yuzu_gw_pending, <<"sweep-expired-2">>)),

    %% Cleanup.
    ets:delete(yuzu_gw_pending, <<"sweep-fresh-1">>).

%%%===================================================================
%%% Monitor ref leak tests
%%%===================================================================

reregister_no_monitor_leak() ->
    %% Register agent, then re-register with a new process.
    %% The old monitor ref should be removed from the map.
    Pid1 = spawn_dummy(),
    Pid2 = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"leak-test">>, Pid1, <<"s1">>, [], <<>>),
    ok = yuzu_gw_registry:register_agent(<<"leak-test">>, Pid2, <<"s2">>, [], <<>>),

    %% Inspect the gen_server state via sys:get_state.
    {state, MonRefs, _SweepTimer} = sys:get_state(yuzu_gw_registry),

    %% There should be exactly one monitor ref for <<"leak-test">>.
    RefCount = length([V || {_, V} <- maps:to_list(MonRefs), V =:= <<"leak-test">>]),
    ?assertEqual(1, RefCount),

    kill_dummy(Pid1),
    kill_dummy(Pid2).

%%%===================================================================
%%% Helpers
%%%===================================================================

spawn_dummy() ->
    spawn(fun() -> receive stop -> ok end end).

kill_dummy(Pid) ->
    Pid ! stop.

collect_all_pages(_Limit, done, Acc) -> Acc;
collect_all_pages(Limit, Cursor, Acc) ->
    {Page, NextCursor} = yuzu_gw_registry:list_agents(Limit, Cursor),
    case Page of
        [] -> Acc;
        _  ->
            Next = case NextCursor of undefined -> done; C -> C end,
            collect_all_pages(Limit, Next, Acc ++ Page)
    end.
