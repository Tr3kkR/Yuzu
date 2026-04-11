%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_mgmt_service — JSON escaping and
%%% management service helpers.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_service_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% JSON escaping tests
%%%===================================================================

json_escape_plain_text_test() ->
    ?assertEqual(<<"hello world">>,
                 yuzu_gw_mgmt_service:json_escape(<<"hello world">>)).

json_escape_double_quotes_test() ->
    ?assertEqual(<<"say \\\"hello\\\"">>,
                 yuzu_gw_mgmt_service:json_escape(<<"say \"hello\"">>)).

json_escape_backslash_test() ->
    ?assertEqual(<<"path\\\\file">>,
                 yuzu_gw_mgmt_service:json_escape(<<"path\\file">>)).

json_escape_newline_test() ->
    ?assertEqual(<<"line1\\nline2">>,
                 yuzu_gw_mgmt_service:json_escape(<<"line1\nline2">>)).

json_escape_carriage_return_test() ->
    ?assertEqual(<<"a\\rb">>,
                 yuzu_gw_mgmt_service:json_escape(<<"a\rb">>)).

json_escape_tab_test() ->
    ?assertEqual(<<"a\\tb">>,
                 yuzu_gw_mgmt_service:json_escape(<<"a\tb">>)).

json_escape_control_chars_test() ->
    %% NUL, SOH, and US (31) should be \u-escaped.
    ?assertEqual(<<"\\u0000\\u0001\\u001f">>,
                 yuzu_gw_mgmt_service:json_escape(<<0, 1, 31>>)).

json_escape_empty_test() ->
    ?assertEqual(<<>>, yuzu_gw_mgmt_service:json_escape(<<>>)).

json_escape_mixed_test() ->
    Input = <<"He said \"hello\\world\"\nand\tthat's it">>,
    Expected = <<"He said \\\"hello\\\\world\\\"\\nand\\tthat's it">>,
    ?assertEqual(Expected, yuzu_gw_mgmt_service:json_escape(Input)).

json_escape_unicode_passthrough_test() ->
    %% Non-ASCII UTF-8 should pass through unchanged.
    Input = <<"café résumé"/utf8>>,
    ?assertEqual(Input, yuzu_gw_mgmt_service:json_escape(Input)).

%%%===================================================================
%%% list_agents Ctx pass-through test
%%%===================================================================

list_agents_passes_ctx_test_() ->
    {setup,
     fun ctx_setup/0,
     fun ctx_cleanup/1,
     [{"list_agents returns caller's ctx", fun list_agents_ctx/0},
      {"get_agent returns caller's ctx on success", fun get_agent_ctx/0}]}.

ctx_setup() ->
    case whereis(yuzu_gw) of
        undefined -> pg:start_link(yuzu_gw);
        _ -> ok
    end,
    case whereis(yuzu_gw_registry) of
        undefined -> {ok, _} = yuzu_gw_registry:start_link();
        _ -> ok
    end,
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(telemetry),
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

ctx_cleanup(_) ->
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(telemetry),
    ok.

list_agents_ctx() ->
    Ctx = #{custom_header => <<"test">>},
    {ok, _Response, ReturnedCtx} = yuzu_gw_mgmt_service:list_agents(
        #{limit => 10}, Ctx),
    ?assertEqual(Ctx, ReturnedCtx).

get_agent_ctx() ->
    %% Register a real agent so get_agent succeeds.
    AgentId = <<"ctx-test-agent">>,
    StreamPid = spawn(fun() -> receive stop -> ok end end),
    Args = #{agent_id => AgentId, session_id => <<"s">>,
             stream_pid => StreamPid,
             agent_info => #{plugins => []}, peer_addr => <<"127.0.0.1">>},
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),
    timer:sleep(20),

    Ctx = #{custom_header => <<"test2">>},
    {ok, _Response, ReturnedCtx} = yuzu_gw_mgmt_service:get_agent(
        #{agent_id => AgentId}, Ctx),
    ?assertEqual(Ctx, ReturnedCtx),

    yuzu_gw_agent:disconnect(AgentPid),
    StreamPid ! stop,
    timer:sleep(50).
