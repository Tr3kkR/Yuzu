%%%-------------------------------------------------------------------
%%% @doc Telemetry event definitions and Prometheus handler.
%%%
%%% All gateway metrics flow through the standard `telemetry` library.
%%% This module:
%%%   1. Defines all event names as a single source of truth.
%%%   2. Attaches a handler that updates Prometheus counters/histograms.
%%%   3. Starts a periodic gauge emitter for BEAM VM stats.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_telemetry).

-export([setup/0, handle_event/4]).

%% All telemetry event names used by the gateway.
-define(EVENTS, [
    %% Agent lifecycle
    [yuzu, gw, agent, connected],
    [yuzu, gw, agent, disconnected],
    [yuzu, gw, agent, count],

    %% Command plane
    [yuzu, gw, command, dispatched],
    [yuzu, gw, command, completed],
    [yuzu, gw, command, timeout],
    [yuzu, gw, command, fanout],

    %% Stream health
    [yuzu, gw, stream, backpressure],
    [yuzu, gw, stream, write_error],

    %% Upstream (C++ server)
    [yuzu, gw, upstream, rpc_latency],
    [yuzu, gw, upstream, rpc_error],

    %% Cluster
    [yuzu, gw, cluster, node_up],
    [yuzu, gw, cluster, node_down],
    [yuzu, gw, cluster, rebalance],

    %% BEAM VM
    [yuzu, gw, vm, process_count],
    [yuzu, gw, vm, memory],
    [yuzu, gw, vm, scheduler_util]
]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Attach all telemetry handlers and start the gauge emitter.
setup() ->
    %% Declare Prometheus metrics.
    declare_metrics(),

    %% Attach event handler.
    telemetry:attach_many(
        yuzu_gw_prometheus,
        ?EVENTS,
        fun ?MODULE:handle_event/4,
        #{}
    ),

    %% Start periodic gauge emitter.
    Interval = application:get_env(yuzu_gw, telemetry_gauge_interval_ms, 10000),
    spawn_link(fun() -> gauge_loop(Interval) end),

    ok.

%%--------------------------------------------------------------------
%% telemetry handler callback
%%--------------------------------------------------------------------

handle_event([yuzu, gw, agent, connected], #{count := N}, Meta, _Config) ->
    Labels = node_labels(Meta),
    prometheus_counter:inc(yuzu_gw_agents_connected_total, Labels, N);

handle_event([yuzu, gw, agent, disconnected], #{count := N, duration_ms := D}, Meta, _Config) ->
    Labels = node_labels(Meta),
    prometheus_counter:inc(yuzu_gw_agents_disconnected_total, Labels, N),
    prometheus_histogram:observe(yuzu_gw_agent_session_duration_ms, Labels, D);

handle_event([yuzu, gw, agent, count], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_agents_current, [node()], N);

handle_event([yuzu, gw, command, dispatched], #{count := N}, Meta, _Config) ->
    Plugin = maps:get(plugin, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_commands_dispatched_total, [Plugin], N);

handle_event([yuzu, gw, command, completed], #{duration_ms := D}, Meta, _Config) ->
    Plugin = maps:get(plugin, Meta, <<"unknown">>),
    Status = maps:get(status, Meta, <<"unknown">>),
    prometheus_histogram:observe(yuzu_gw_command_duration_ms, [Plugin, Status], D);

handle_event([yuzu, gw, command, timeout], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_commands_timed_out_total, [], N);

handle_event([yuzu, gw, command, fanout], #{target_count := T, dispatched := D}, _Meta, _Config) ->
    prometheus_histogram:observe(yuzu_gw_fanout_target_count, [], T),
    prometheus_histogram:observe(yuzu_gw_fanout_dispatched_count, [], D);

handle_event([yuzu, gw, stream, backpressure], #{queue_len := Q}, Meta, _Config) ->
    AgentId = maps:get(agent_id, Meta, <<"unknown">>),
    prometheus_gauge:set(yuzu_gw_stream_queue_len, [AgentId], Q);

handle_event([yuzu, gw, stream, write_error], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_stream_write_errors_total, [], N);

handle_event([yuzu, gw, upstream, rpc_latency], #{duration_ms := D}, Meta, _Config) ->
    RpcName = maps:get(rpc_name, Meta, <<"unknown">>),
    prometheus_histogram:observe(yuzu_gw_upstream_rpc_duration_ms, [RpcName], D);

handle_event([yuzu, gw, upstream, rpc_error], #{count := N}, Meta, _Config) ->
    RpcName = maps:get(rpc_name, Meta, <<"unknown">>),
    Code = maps:get(code, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_upstream_rpc_errors_total, [RpcName, Code], N);

handle_event([yuzu, gw, cluster, node_up], _Measurements, Meta, _Config) ->
    Node = maps:get(node, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_cluster_events_total, [<<"node_up">>, Node], 1);

handle_event([yuzu, gw, cluster, node_down], _Measurements, Meta, _Config) ->
    Node = maps:get(node, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_cluster_events_total, [<<"node_down">>, Node], 1);

handle_event([yuzu, gw, cluster, rebalance], #{moved_agents := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_cluster_rebalanced_agents_total, [], N);

handle_event([yuzu, gw, vm, process_count], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_process_count, [node()], N);

handle_event([yuzu, gw, vm, memory], Measurements, _Meta, _Config) ->
    Node = node(),
    maps:foreach(fun(Type, Bytes) ->
        prometheus_gauge:set(yuzu_gw_beam_memory_bytes, [Node, Type], Bytes)
    end, Measurements);

handle_event([yuzu, gw, vm, scheduler_util], #{weighted_avg := Avg}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_scheduler_util, [node()], Avg);

handle_event(_Event, _Measurements, _Meta, _Config) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

declare_metrics() ->
    %% Counters
    prometheus_counter:declare([
        {name, yuzu_gw_agents_connected_total},
        {labels, [node]},
        {help, "Total agent connections accepted"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_agents_disconnected_total},
        {labels, [node]},
        {help, "Total agent disconnections"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_commands_dispatched_total},
        {labels, [plugin]},
        {help, "Total commands dispatched to agents"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_commands_timed_out_total},
        {labels, []},
        {help, "Total commands that timed out"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_stream_write_errors_total},
        {labels, []},
        {help, "Total gRPC stream write errors"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_upstream_rpc_errors_total},
        {labels, [rpc_name, code]},
        {help, "Upstream RPC errors by method and status code"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_events_total},
        {labels, [event, node]},
        {help, "Cluster membership events"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_rebalanced_agents_total},
        {labels, []},
        {help, "Total agents moved during rebalancing"}]),

    %% Histograms
    Buckets = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000],
    prometheus_histogram:declare([
        {name, yuzu_gw_agent_session_duration_ms},
        {labels, [node]},
        {buckets, [1000, 10000, 60000, 300000, 3600000]},
        {help, "Agent session duration in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_command_duration_ms},
        {labels, [plugin, status]},
        {buckets, Buckets},
        {help, "Command execution duration in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_upstream_rpc_duration_ms},
        {labels, [rpc_name]},
        {buckets, Buckets},
        {help, "Upstream C++ server RPC latency in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_target_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents targeted per command fanout"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_dispatched_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents actually dispatched per fanout"}]),

    %% Gauges
    prometheus_gauge:declare([
        {name, yuzu_gw_agents_current},
        {labels, [node]},
        {help, "Current number of connected agents"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_stream_queue_len},
        {labels, [agent_id]},
        {help, "Agent process mailbox queue length"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_process_count},
        {labels, [node]},
        {help, "BEAM VM process count"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_memory_bytes},
        {labels, [node, type]},
        {help, "BEAM VM memory usage by type"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_scheduler_util},
        {labels, [node]},
        {help, "BEAM scheduler utilization (weighted average)"}]),

    ok.

%% Periodic gauge emitter for agent count and BEAM VM stats.
gauge_loop(Interval) ->
    timer:sleep(Interval),

    %% Agent count
    Count = yuzu_gw_registry:agent_count(),
    telemetry:execute([yuzu, gw, agent, count],
                      #{count => Count}, #{}),

    %% BEAM process count
    telemetry:execute([yuzu, gw, vm, process_count],
                      #{count => erlang:system_info(process_count)}, #{}),

    %% BEAM memory
    Mem = erlang:memory(),
    telemetry:execute([yuzu, gw, vm, memory],
                      #{total     => proplists:get_value(total, Mem, 0),
                        processes => proplists:get_value(processes, Mem, 0),
                        ets       => proplists:get_value(ets, Mem, 0),
                        binary    => proplists:get_value(binary, Mem, 0)},
                      #{}),

    %% Scheduler utilization
    case erlang:statistics(scheduler_wall_time_all) of
        undefined ->
            ok;
        SchedTimes ->
            Total = lists:sum([A || {_, A, _} <- SchedTimes]),
            Active = lists:sum([W || {_, _, W} <- SchedTimes]),
            Avg = case Total of
                0 -> 0.0;
                _ -> Active / Total
            end,
            telemetry:execute([yuzu, gw, vm, scheduler_util],
                              #{weighted_avg => Avg}, #{})
    end,

    gauge_loop(Interval).

node_labels(Meta) ->
    [maps:get(node, Meta, node())].
