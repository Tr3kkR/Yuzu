%%%-------------------------------------------------------------------
%%% @doc Supervised periodic gauge emitter for BEAM VM and agent metrics.
%%%
%%% Emits telemetry events at a configurable interval:
%%%   - Agent count (from ETS registry)
%%%   - BEAM process count
%%%   - BEAM memory breakdown
%%%   - Scheduler utilization (delta-based)
%%%
%%% Scheduler utilization is computed from wall-time deltas between
%%% consecutive snapshots, giving recent utilization rather than
%%% cumulative averages.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_gauge).
-behaviour(gen_server).

-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-ifdef(TEST).
-export([compute_scheduler_util/2]).
-endif.

-define(SERVER, ?MODULE).

-record(state, {
    interval   :: pos_integer(),
    prev_sched :: [{pos_integer(), pos_integer(), pos_integer()}] | undefined
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Interval = application:get_env(yuzu_gw, telemetry_gauge_interval_ms, 10000),
    %% Enable scheduler wall time tracking for utilization metrics.
    erlang:system_flag(scheduler_wall_time, true),
    PrevSched = erlang:statistics(scheduler_wall_time_all),
    erlang:send_after(Interval, self(), tick),
    {ok, #state{interval = Interval, prev_sched = PrevSched}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(tick, #state{interval = Interval, prev_sched = PrevSched} = State) ->
    %% Agent count — guard against registry not being up yet.
    Count = try yuzu_gw_registry:agent_count() catch _:_ -> 0 end,
    telemetry:execute([yuzu, gw, agent, count], #{count => Count}, #{}),

    %% BEAM process count.
    telemetry:execute([yuzu, gw, vm, process_count],
                      #{count => erlang:system_info(process_count)}, #{}),

    %% BEAM memory breakdown.
    Mem = erlang:memory(),
    telemetry:execute([yuzu, gw, vm, memory],
                      #{total     => proplists:get_value(total, Mem, 0),
                        processes => proplists:get_value(processes, Mem, 0),
                        ets       => proplists:get_value(ets, Mem, 0),
                        binary    => proplists:get_value(binary, Mem, 0)},
                      #{}),

    %% Scheduler utilization (delta-based).
    NewPrevSched = emit_scheduler_util(PrevSched),

    erlang:send_after(Interval, self(), tick),
    {noreply, State#state{prev_sched = NewPrevSched}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

emit_scheduler_util(PrevSched) ->
    case erlang:statistics(scheduler_wall_time_all) of
        undefined ->
            PrevSched;
        CurrSched when PrevSched =:= undefined ->
            %% First snapshot — no delta available yet.
            CurrSched;
        CurrSched ->
            Avg = compute_scheduler_util(PrevSched, CurrSched),
            telemetry:execute([yuzu, gw, vm, scheduler_util],
                              #{weighted_avg => Avg}, #{}),
            CurrSched
    end.

%% @doc Compute scheduler utilization from two wall-time snapshots.
%% Returns a float in [0.0, 1.0].
%% Each snapshot is [{SchedulerId, ActiveTime, TotalTime}].
compute_scheduler_util(PrevSched, CurrSched) ->
    PrevMap = maps:from_list(
        [{Id, {Active, Total}} || {Id, Active, Total} <- PrevSched]),
    {DeltaActive, DeltaTotal} = lists:foldl(
        fun({Id, CurrActive, CurrTotal}, {AccActive, AccTotal}) ->
            case maps:find(Id, PrevMap) of
                {ok, {PrevActive, PrevTotal}} ->
                    {AccActive + (CurrActive - PrevActive),
                     AccTotal + (CurrTotal - PrevTotal)};
                error ->
                    {AccActive, AccTotal}
            end
        end, {0, 0}, CurrSched),
    case DeltaTotal of
        0 -> 0.0;
        _ -> DeltaActive / DeltaTotal
    end.
