%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_app — distribution cookie guard (#659).
%%%
%%% evaluate_cookie/3 is the pure policy decision behind the boot guard
%%% that refuses to start with a known-insecure Erlang distribution cookie
%%% (the cookie is the sole authentication for inter-node RPC; a publicly
%%% known value is unauthenticated remote code execution via EPMD).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app_tests).
-include_lib("eunit/include/eunit.hrl").

%% A non-distributed node has no inter-node attack surface, so no cookie is
%% ever rejected — this keeps eunit/CT (which run as nonode@nohost) unaffected.
non_distributed_accepts_any_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', 'yuzu_gw_secret_change_me', false)),
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', '', false)).

%% The historical committed default must fail closed once distribution is up.
default_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', false)).

%% An empty cookie (e.g. unsubstituted ${YUZU_GW_COOKIE}) is equally insecure.
empty_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '', false)).

%% The explicit dev/CI override permits the default cookie.
override_allows_default_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', true)).

%% A strong unique cookie is accepted when distributed.
strong_cookie_accepted_when_distributed_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    'a3f9c1e2b7d84056a3f9c1e2b7d84056f0e1d2c3', false)).

%% #659 UP-1: if relx `.src` substitution fails, the cookie atom is the literal
%% `${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}`. Substring matching must catch it
%% (it embeds the default), otherwise the unauthenticated-RPC surface re-opens.
literal_unsubstituted_default_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    '${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}', false)).

%% A bare unsubstituted placeholder (no fallback) is rejected via the `${` check.
unsubstituted_placeholder_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '${YUZU_GW_COOKIE}', false)).
