%%%-------------------------------------------------------------------
%%% @doc Shared performance test utilities.
%%%
%%% Provides latency measurement with percentile computation,
%%% agent spawning/cleanup, memory tracking, and structured
%%% assertion helpers for the performance test suites.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_perf_helpers).

-export([
    get_env/2,
    measure_latency/2,
    stats_from_timings/1,
    measure_wall_clock/1,
    measure_wall_clock_us/1,
    spawn_agents/2,
    spawn_and_register/2,
    cleanup_agents/1,
    assert_latency/2,
    assert_throughput/3,
    assert_throughput_us/3,
    memory_snapshot/0,
    memory_delta/2,
    format_report/2,
    format_stats/1,
    wait_for_registry_count/2
]).

%%%===================================================================
%%% Configuration
%%%===================================================================

%% @doc Read an integer environment variable, falling back to Default.
-spec get_env(string(), integer()) -> integer().
get_env(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> list_to_integer(Val)
    end.

%%%===================================================================
%%% Timing
%%%===================================================================

%% @doc Run Fun N times sequentially, collect µs timings, return stats.
%%
%% Returns #{min, max, mean, p50, p95, p99, stddev, n, sum} in µs.
-spec measure_latency(fun(() -> term()), pos_integer()) -> map().
measure_latency(Fun, N) when N > 0 ->
    Timings = [begin
        T0 = erlang:monotonic_time(microsecond),
        Fun(),
        T1 = erlang:monotonic_time(microsecond),
        T1 - T0
    end || _ <- lists:seq(1, N)],
    compute_stats(lists:sort(Timings)).

%% @doc Compute stats from a raw list of µs timings.
-spec stats_from_timings([non_neg_integer()]) -> map().
stats_from_timings(Timings) when length(Timings) > 0 ->
    compute_stats(lists:sort(Timings)).

%% @doc Measure wall-clock time of Fun() in milliseconds.
-spec measure_wall_clock(fun(() -> T)) -> {non_neg_integer(), T}.
measure_wall_clock(Fun) ->
    T0 = erlang:monotonic_time(millisecond),
    Result = Fun(),
    T1 = erlang:monotonic_time(millisecond),
    {T1 - T0, Result}.

%% @doc Measure wall-clock time of Fun() in microseconds.
%% Use this for sub-millisecond benchmarks. heartbeat_throughput at the
%% default 20K-op count completes in ~8 ms, which gave only 7/8/9 ms
%% (3 buckets) under measure_wall_clock/1; the corresponding ops/sec
%% values were quantized to 2.22M / 2.5M / 2.86M and a 10% perf-gate
%% tolerance couldn't survive a single-ms tick. Microsecond resolution
%% turns those 3 buckets into thousands.
-spec measure_wall_clock_us(fun(() -> T)) -> {non_neg_integer(), T}.
measure_wall_clock_us(Fun) ->
    T0 = erlang:monotonic_time(microsecond),
    Result = Fun(),
    T1 = erlang:monotonic_time(microsecond),
    {T1 - T0, Result}.

%%%===================================================================
%%% Agent management
%%%===================================================================

%% @doc Spawn N dummy processes that loop until killed.
%% Uses spawn (not spawn_link) to avoid exit-signal cascades in CT.
%% Returns {Pids, Ids} — IDs are binaries like <<"perf-000001">>.
-spec spawn_agents(pos_integer(), map()) -> {[pid()], [binary()]}.
spawn_agents(N, Opts) ->
    Prefix = maps:get(prefix, Opts, <<"perf">>),
    lists:unzip([begin
        Id = iolist_to_binary(io_lib:format("~s-~6..0B", [Prefix, I])),
        Pid = spawn(fun agent_loop/0),
        {Pid, Id}
    end || I <- lists:seq(1, N)]).

%% @doc Spawn N dummy processes and register them with the gateway registry.
%% Options: prefix (binary), plugins (list of binaries).
-spec spawn_and_register(pos_integer(), map()) -> {[pid()], [binary()]}.
spawn_and_register(N, Opts) ->
    Plugins = maps:get(plugins, Opts, [<<"plugin1">>]),
    Prefix = maps:get(prefix, Opts, <<"perf">>),
    lists:unzip([begin
        Id = iolist_to_binary(io_lib:format("~s-~6..0B", [Prefix, I])),
        Pid = spawn(fun agent_loop/0),
        SessionId = <<"sess-", Id/binary>>,
        ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, Plugins, <<>>),
        {Pid, Id}
    end || I <- lists:seq(1, N)]).

%% @doc Kill all agent processes. Waits briefly for monitor-based cleanup.
-spec cleanup_agents([pid()]) -> ok.
cleanup_agents(Pids) ->
    lists:foreach(fun(Pid) ->
        case is_process_alive(Pid) of
            true  -> exit(Pid, kill);
            false -> ok
        end
    end, Pids),
    ok.

%%%===================================================================
%%% Assertions
%%%===================================================================

%% @doc Assert that latency stats satisfy constraints.
%% Constraints is a map of #{metric_name => max_microseconds}.
%% Example: assert_latency(Stats, #{p99 => 1000, mean => 500}).
-spec assert_latency(map(), map()) -> ok.
assert_latency(Stats, Constraints) ->
    maps:foreach(fun(Key, MaxVal) ->
        Actual = maps:get(Key, Stats),
        case Actual =< MaxVal of
            true -> ok;
            false ->
                erlang:error({latency_assertion_failed,
                    [{metric, Key},
                     {actual_us, Actual},
                     {limit_us, MaxVal},
                     {full_stats, format_stats(Stats)}]})
        end
    end, Constraints).

%% @doc Log throughput and return ops/sec.
-spec assert_throughput(string(), non_neg_integer(), non_neg_integer()) -> float().
assert_throughput(Label, N, WallMs) when WallMs > 0 ->
    OpsPerSec = N * 1000.0 / WallMs,
    ct:pal("~s: ~B ops in ~B ms (~B ops/sec)", [Label, N, WallMs, round(OpsPerSec)]),
    OpsPerSec;
assert_throughput(Label, N, _WallMs) ->
    ct:pal("~s: ~B ops in <1 ms (instant)", [Label, N]),
    infinity.

%% @doc Log throughput from a microsecond elapsed time. Output format
%% keeps the trailing "(NNN ops/sec)" so the perf-gate.sh parser regex
%% (which is unit-agnostic) continues to match without changes.
-spec assert_throughput_us(string(), non_neg_integer(), non_neg_integer()) -> float().
assert_throughput_us(Label, N, WallUs) when WallUs > 0 ->
    OpsPerSec = N * 1000000.0 / WallUs,
    ct:pal("~s: ~B ops in ~B us (~B ops/sec)", [Label, N, WallUs, round(OpsPerSec)]),
    OpsPerSec;
assert_throughput_us(Label, N, _WallUs) ->
    ct:pal("~s: ~B ops in <1 us (instant)", [Label, N]),
    infinity.

%%%===================================================================
%%% Memory tracking
%%%===================================================================

%% @doc Capture a snapshot of BEAM memory + process/ETS counts.
-spec memory_snapshot() -> map().
memory_snapshot() ->
    #{
        total         => erlang:memory(total),
        ets           => erlang:memory(ets),
        processes     => erlang:memory(processes),
        binary        => erlang:memory(binary),
        process_count => erlang:system_info(process_count),
        ets_agent_size => try ets:info(yuzu_gw_agents, size) catch _:_ -> 0 end
    }.

%% @doc Compute element-wise delta between two snapshots.
-spec memory_delta(map(), map()) -> map().
memory_delta(Before, After) ->
    maps:map(fun(Key, AfterVal) ->
        AfterVal - maps:get(Key, Before, 0)
    end, After).

%%%===================================================================
%%% Formatting
%%%===================================================================

%% @doc Format a named test report with stats for CT HTML logs.
-spec format_report(string(), map()) -> iolist().
format_report(TestName, Stats) ->
    io_lib:format("~n=== ~s ===~n~s~n", [TestName, format_stats(Stats)]).

%% @doc Format a stats map as a single-line summary.
-spec format_stats(map()) -> iolist().
format_stats(Stats) ->
    io_lib:format(
        "  n=~B  min=~.1fus  mean=~.1fus  p50=~.1fus  "
        "p95=~.1fus  p99=~.1fus  max=~.1fus  stddev=~.1fus",
        [maps:get(n, Stats),
         float(maps:get(min, Stats)),  float(maps:get(mean, Stats)),
         float(maps:get(p50, Stats)),  float(maps:get(p95, Stats)),
         float(maps:get(p99, Stats)),  float(maps:get(max, Stats)),
         float(maps:get(stddev, Stats))]).

%%%===================================================================
%%% Polling
%%%===================================================================

%% @doc Poll until the gateway registry reaches TargetCount (0 = empty).
-spec wait_for_registry_count(non_neg_integer(), pos_integer()) -> ok | {error, term()}.
wait_for_registry_count(TargetCount, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_registry_loop(TargetCount, Deadline).

%%%===================================================================
%%% Internal
%%%===================================================================

agent_loop() ->
    receive stop -> ok; _ -> agent_loop() end.

compute_stats(Sorted) ->
    N = length(Sorted),
    Sum = lists:sum(Sorted),
    Min = hd(Sorted),
    Max = lists:last(Sorted),
    Mean = Sum / N,
    P50 = percentile_idx(Sorted, N, 50),
    P95 = percentile_idx(Sorted, N, 95),
    P99 = percentile_idx(Sorted, N, 99),
    Variance = lists:foldl(fun(V, Acc) ->
        D = V - Mean,
        Acc + D * D
    end, 0.0, Sorted) / N,
    StdDev = math:sqrt(Variance),
    #{min => Min, max => Max, mean => Mean,
      p50 => P50, p95 => P95, p99 => P99,
      stddev => StdDev, n => N, sum => Sum}.

percentile_idx(Sorted, N, P) ->
    Idx = max(1, min(N, round(P / 100 * N))),
    lists:nth(Idx, Sorted).

wait_registry_loop(TargetCount, Deadline) ->
    case yuzu_gw_registry:agent_count() of
        TargetCount -> ok;
        Count ->
            Now = erlang:monotonic_time(millisecond),
            case Now >= Deadline of
                true  -> {error, {expected, TargetCount, got, Count}};
                false -> timer:sleep(50), wait_registry_loop(TargetCount, Deadline)
            end
    end.
