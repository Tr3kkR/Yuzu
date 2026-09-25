%%%-------------------------------------------------------------------
%%% @doc EUnit tests for yuzu_gw_telemetry's event -> Prometheus wiring.
%%%
%%% HA WS-4 4.4 round-2 review (Gate 3 finding NEW-1, Gate 6 findings
%%% COMP-1/COMP-2/NEW-2): the original F2 fix (yuzu_gw_upstream emitting
%%% `[yuzu, gw, upstream, notify_dropped]`) was asserted "Fixed" but the
%%% event was never added to yuzu_gw_telemetry's ?EVENTS list, handle_event/4
%%% clauses, or declare_metrics/0 -- so telemetry:execute/3 on that event
%%% name was a pure no-op (an unattached event name), and the drop stayed
%%% exactly as invisible as before the "fix". Every OTHER producer module's
%%% own tests mock the `telemetry` module entirely (meck `execute` ->
%%% `ok`), which verifies the EMISSION call happened but can NEVER catch a
%%% CONSUMPTION-side wiring gap like this one -- this file exists
%%% specifically to close that blind spot, mirroring
%%% yuzu_gw_authz_tests.erl's own `telemetry_counter_test_` precedent: fire
%%% the REAL event through the REAL attached handler (no meck on
%%% `telemetry` at all) and assert the Prometheus counter actually moves.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_telemetry_tests).
-include_lib("eunit/include/eunit.hrl").

notify_dropped_test_() ->
    {setup,
     fun() ->
        {ok, Started} = application:ensure_all_started(prometheus),
        {ok, Started2} = application:ensure_all_started(telemetry),
        %% A prior test module's own yuzu_gw_telemetry:setup() call (or a
        %% leaked yuzu_gw_app boot) may have already attached this handler
        %% id -- detach first so re-attaching here is not a silent no-op
        %% under {error, already_exists} (mirrors the authz precedent).
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        Started ++ Started2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"circuit_open drop reaches the real Prometheus counter",
       fun() ->
           Before = counter_val(yuzu_gw_upstream_notify_dropped_total,
                                 [<<"circuit_open">>]),
           telemetry:execute([yuzu, gw, upstream, notify_dropped],
                             #{count => 1}, #{reason => <<"circuit_open">>}),
           ?assertEqual(Before + 1,
                        counter_val(yuzu_gw_upstream_notify_dropped_total,
                                    [<<"circuit_open">>]))
       end},
      {"at_capacity drop reaches the real Prometheus counter, labeled "
       "distinctly from circuit_open",
       fun() ->
           Before = counter_val(yuzu_gw_upstream_notify_dropped_total,
                                 [<<"at_capacity">>]),
           telemetry:execute([yuzu, gw, upstream, notify_dropped],
                             #{count => 1}, #{reason => <<"at_capacity">>}),
           ?assertEqual(Before + 1,
                        counter_val(yuzu_gw_upstream_notify_dropped_total,
                                    [<<"at_capacity">>]))
       end}
     ]}.

%% #4707: a single non-Latin-1 character (an em dash) in one metric's HELP
%% string made prometheus_text_format crash with badarg on every scrape, so
%% :9568/metrics answered HTTP 500 for the whole registry. The CT suite that
%% scrapes the endpoint was masked by #4800 (zero suites ran), so the defect
%% shipped. This renders the REAL registry after the REAL setup through the
%% REAL text formatter, in eunit, so the regression fails the fast gate.
scrape_renders_test_() ->
    {setup,
     fun() ->
        {ok, _} = application:ensure_all_started(prometheus),
        {ok, _} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup()
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"the default registry renders to Prometheus text without crashing",
       fun() ->
           Text = prometheus_text_format:format(default),
           ?assert(is_binary(Text)),
           ?assertNotEqual(nomatch,
                           binary:match(Text, <<"yuzu_gw_agents_connected_total">>))
       end},
      {"every yuzu_gw_* HELP line is plain ASCII",
       fun() ->
           Text = prometheus_text_format:format(default),
           Bad = [L || L <- binary:split(Text, <<"\n">>, [global]),
                       binary:match(L, <<"# HELP yuzu_gw_">>) =/= nomatch,
                       lists:any(fun(C) -> C > 127 end, binary_to_list(L))],
           ?assertEqual([], Bad)
       end}
     ]}.

counter_val(Name, Labels) ->
    case prometheus_counter:value(Name, Labels) of
        undefined -> 0;
        V -> V
    end.
