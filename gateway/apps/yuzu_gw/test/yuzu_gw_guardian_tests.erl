%%%-------------------------------------------------------------------
%%% @doc Unit tests for the Guardian side-channel classifier.
%%%
%%% Covers the pure paths: frame classification (is_guardian_frame/1) and
%%% intercept/2's `passthrough` decision (no side effect). The `forwarded`
%%% branch casts into the yuzu_gw_upstream gen_server and is exercised
%%% end-to-end in the gateway UAT, not here.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_guardian_tests).
-include_lib("eunit/include/eunit.hrl").

%% gpb maps decode yields atom keys — the production shape.
is_guardian_frame_atom_key_test() ->
    ?assert(yuzu_gw_guardian:is_guardian_frame(
              #{plugin => <<"__guard__">>, action => <<"event">>})).

%% Binary-key fallback (matches yuzu_gw_agent's command_id/plugin reads).
is_guardian_frame_binary_key_test() ->
    ?assert(yuzu_gw_guardian:is_guardian_frame(
              #{<<"plugin">> => <<"__guard__">>})).

non_guardian_plugin_test() ->
    ?assertNot(yuzu_gw_guardian:is_guardian_frame(
                 #{plugin => <<"inventory">>, command_id => <<"c1">>})).

missing_plugin_field_test() ->
    %% A normal command response has no `plugin` field.
    ?assertNot(yuzu_gw_guardian:is_guardian_frame(
                 #{command_id => <<"c1">>, status => 'SUCCESS'})).

non_map_frame_test() ->
    %% Defensive: a malformed (non-map) frame must not crash the classifier.
    ?assertNot(yuzu_gw_guardian:is_guardian_frame(<<"garbage">>)),
    ?assertNot(yuzu_gw_guardian:is_guardian_frame(undefined)).

intercept_passthrough_test() ->
    %% A non-Guardian frame returns passthrough with no upstream interaction.
    ?assertEqual(passthrough,
                 yuzu_gw_guardian:intercept(<<"agent-1">>,
                                            #{plugin => <<"inventory">>,
                                              command_id => <<"c1">>})).
