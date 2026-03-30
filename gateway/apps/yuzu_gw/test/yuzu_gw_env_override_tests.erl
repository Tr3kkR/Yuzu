%%%-------------------------------------------------------------------
%%% @doc Non-functional EUnit tests for C1: TLS configuration and
%%% environment variable overrides.
%%%
%%% Tests apply_env_overrides/0 and apply_tls_overrides/0 with
%%% various valid, invalid, and partial environment variable
%%% combinations. Verifies that the config system is robust
%%% against malformed input and correctly propagates overrides.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_env_override_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — foreach clears env between tests
%%%===================================================================

env_override_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"integer env overrides are applied", fun integer_overrides/0},
      {"boolean env override: true/false strings", fun bool_override_strings/0},
      {"boolean env override: 1/0 strings", fun bool_override_numeric/0},
      {"invalid integer env override is ignored", fun invalid_integer_ignored/0},
      {"invalid boolean env override is ignored", fun invalid_bool_ignored/0},
      {"TLS cert env overrides set tls proplist", fun tls_cert_overrides/0},
      {"partial TLS cert env override merges with base", fun partial_tls_cert_override/0},
      {"TLS cert override with no base creates new proplist", fun tls_cert_override_no_base/0},
      {"env overrides do not clobber unrelated config", fun no_clobber/0},
      {"all env vars absent leaves defaults untouched", fun absent_env_noop/0}
     ]}.

setup() ->
    %% Save original env state for restoration.
    %% Clear any leftover env vars from prior tests.
    EnvVars = [
        "YUZU_GW_UPSTREAM_ADDR", "YUZU_GW_UPSTREAM_PORT",
        "YUZU_GW_AGENT_PORT", "YUZU_GW_MGMT_PORT",
        "YUZU_GW_PROMETHEUS_PORT", "YUZU_GW_HEALTH_PORT",
        "YUZU_GW_HEARTBEAT_INTERVAL_MS", "YUZU_GW_COMMAND_TIMEOUT_S",
        "YUZU_GW_BACKPRESSURE_THRESHOLD",
        "YUZU_GW_CB_FAILURE_THRESHOLD", "YUZU_GW_CB_RESET_TIMEOUT_MS",
        "YUZU_GW_CB_MAX_RESET_TIMEOUT_MS",
        "YUZU_GW_TLS_ENABLED",
        "YUZU_GW_TLS_CERTFILE", "YUZU_GW_TLS_KEYFILE", "YUZU_GW_TLS_CACERTFILE"
    ],
    lists:foreach(fun(V) -> os:unsetenv(V) end, EnvVars),
    %% Set known defaults so we can verify they're changed.
    application:set_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    application:set_env(yuzu_gw, upstream_port, 50055),
    application:set_env(yuzu_gw, health_port, 8081),
    application:set_env(yuzu_gw, backpressure_threshold, 1000),
    application:unset_env(yuzu_gw, tls_enabled),
    application:unset_env(yuzu_gw, tls),
    EnvVars.

cleanup(EnvVars) ->
    lists:foreach(fun(V) -> os:unsetenv(V) end, EnvVars),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

integer_overrides() ->
    os:putenv("YUZU_GW_UPSTREAM_PORT", "9999"),
    os:putenv("YUZU_GW_HEALTH_PORT", "18888"),
    os:putenv("YUZU_GW_BACKPRESSURE_THRESHOLD", "500"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(9999, application:get_env(yuzu_gw, upstream_port, undefined)),
    ?assertEqual(18888, application:get_env(yuzu_gw, health_port, undefined)),
    ?assertEqual(500, application:get_env(yuzu_gw, backpressure_threshold, undefined)).

bool_override_strings() ->
    os:putenv("YUZU_GW_TLS_ENABLED", "false"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(false, application:get_env(yuzu_gw, tls_enabled, undefined)),

    os:putenv("YUZU_GW_TLS_ENABLED", "true"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(true, application:get_env(yuzu_gw, tls_enabled, undefined)).

bool_override_numeric() ->
    os:putenv("YUZU_GW_TLS_ENABLED", "0"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(false, application:get_env(yuzu_gw, tls_enabled, undefined)),

    os:putenv("YUZU_GW_TLS_ENABLED", "1"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(true, application:get_env(yuzu_gw, tls_enabled, undefined)).

invalid_integer_ignored() ->
    application:set_env(yuzu_gw, upstream_port, 50055),
    os:putenv("YUZU_GW_UPSTREAM_PORT", "not_a_number"),
    yuzu_gw_app:apply_env_overrides(),
    %% Original value preserved.
    ?assertEqual(50055, application:get_env(yuzu_gw, upstream_port, undefined)).

invalid_bool_ignored() ->
    application:unset_env(yuzu_gw, tls_enabled),
    os:putenv("YUZU_GW_TLS_ENABLED", "maybe"),
    yuzu_gw_app:apply_env_overrides(),
    %% tls_enabled should not be set (error was caught and ignored).
    ?assertEqual(undefined, application:get_env(yuzu_gw, tls_enabled, undefined)).

tls_cert_overrides() ->
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/test.crt"),
    os:putenv("YUZU_GW_TLS_KEYFILE", "/tmp/test.key"),
    os:putenv("YUZU_GW_TLS_CACERTFILE", "/tmp/ca.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/test.crt", proplists:get_value(certfile, TlsOpts)),
    ?assertEqual("/tmp/test.key", proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual("/tmp/ca.crt", proplists:get_value(cacertfile, TlsOpts)).

partial_tls_cert_override() ->
    %% Set a base TLS config.
    application:set_env(yuzu_gw, tls, [
        {certfile, "/etc/yuzu/old.crt"},
        {keyfile,  "/etc/yuzu/old.key"},
        {verify, verify_peer}
    ]),
    %% Only override certfile, leave keyfile and verify alone.
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/new.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/new.crt", proplists:get_value(certfile, TlsOpts)),
    ?assertEqual("/etc/yuzu/old.key", proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual(verify_peer, proplists:get_value(verify, TlsOpts)).

tls_cert_override_no_base() ->
    %% No base TLS config at all.
    application:unset_env(yuzu_gw, tls),
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/brand-new.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/brand-new.crt", proplists:get_value(certfile, TlsOpts)),
    %% keyfile and cacertfile should not be present.
    ?assertEqual(undefined, proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual(undefined, proplists:get_value(cacertfile, TlsOpts)).

no_clobber() ->
    %% Set an unrelated config key.
    application:set_env(yuzu_gw, hash_ring_vnodes, 256),
    %% Apply an override to a different key.
    os:putenv("YUZU_GW_UPSTREAM_ADDR", "10.0.0.1"),
    yuzu_gw_app:apply_env_overrides(),
    %% Unrelated key must be untouched.
    ?assertEqual(256, application:get_env(yuzu_gw, hash_ring_vnodes, undefined)),
    ?assertEqual("10.0.0.1", application:get_env(yuzu_gw, upstream_addr, undefined)).

absent_env_noop() ->
    %% No env vars set at all. Defaults should remain.
    application:set_env(yuzu_gw, upstream_port, 50055),
    application:set_env(yuzu_gw, health_port, 8081),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(50055, application:get_env(yuzu_gw, upstream_port, undefined)),
    ?assertEqual(8081, application:get_env(yuzu_gw, health_port, undefined)).
