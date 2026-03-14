%%%-------------------------------------------------------------------
%%% @doc Protobuf encode/decode helpers and type conversion utilities.
%%%
%%% Wraps gpb-generated modules to provide a clean API for the rest
%%% of the gateway. Handles the map ↔ proto record translation and
%%% provides convenience functions for common field access patterns.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_proto).

-export([
    %% Timestamp helpers
    now_timestamp/0,
    timestamp_to_millis/1,
    millis_to_timestamp/1,

    %% CommandRequest/Response helpers
    command_id/1,
    command_plugin/1,
    command_action/1,
    response_status/1,
    is_terminal_status/1,

    %% AgentInfo helpers
    agent_id/1,
    agent_hostname/1,
    agent_plugins/1,

    %% Encoding
    encode_command_request/1,
    encode_command_response/1,
    encode_send_command_response/2,
    encode_agent_event/3
]).

%%%===================================================================
%%% Timestamp helpers
%%%===================================================================

%% @doc Return a proto Timestamp map for the current time.
-spec now_timestamp() -> map().
now_timestamp() ->
    #{millis_epoch => erlang:system_time(millisecond)}.

%% @doc Extract milliseconds from a Timestamp map.
-spec timestamp_to_millis(map() | undefined) -> integer().
timestamp_to_millis(undefined) -> 0;
timestamp_to_millis(#{millis_epoch := M}) -> M;
timestamp_to_millis(#{<<"millis_epoch">> := M}) -> M;
timestamp_to_millis(_) -> 0.

%% @doc Build a Timestamp map from milliseconds.
-spec millis_to_timestamp(integer()) -> map().
millis_to_timestamp(Millis) ->
    #{millis_epoch => Millis}.

%%%===================================================================
%%% CommandRequest field accessors
%%%===================================================================

%% @doc Extract command_id from a CommandRequest map.
-spec command_id(map()) -> binary().
command_id(Cmd) ->
    maps:get(command_id, Cmd,
             maps:get(<<"command_id">>, Cmd, <<>>)).

%% @doc Extract plugin name from a CommandRequest map.
-spec command_plugin(map()) -> binary().
command_plugin(Cmd) ->
    maps:get(plugin, Cmd,
             maps:get(<<"plugin">>, Cmd, <<>>)).

%% @doc Extract action from a CommandRequest map.
-spec command_action(map()) -> binary().
command_action(Cmd) ->
    maps:get(action, Cmd,
             maps:get(<<"action">>, Cmd, <<>>)).

%%%===================================================================
%%% CommandResponse field accessors
%%%===================================================================

%% @doc Extract status from a CommandResponse map.
-spec response_status(map()) -> atom() | binary() | integer().
response_status(Resp) ->
    maps:get(status, Resp,
             maps:get(<<"status">>, Resp, undefined)).

%% @doc Check if a response status is terminal (not RUNNING).
-spec is_terminal_status(atom() | binary() | integer()) -> boolean().
is_terminal_status('RUNNING')     -> false;
is_terminal_status(<<"RUNNING">>) -> false;
is_terminal_status(0)             -> false;  %% proto enum value for RUNNING
is_terminal_status(_)             -> true.

%%%===================================================================
%%% AgentInfo field accessors
%%%===================================================================

%% @doc Extract agent_id from an AgentInfo map.
-spec agent_id(map()) -> binary().
agent_id(Info) ->
    maps:get(agent_id, Info,
             maps:get(<<"agent_id">>, Info, <<>>)).

%% @doc Extract hostname from an AgentInfo map.
-spec agent_hostname(map()) -> binary().
agent_hostname(Info) ->
    maps:get(hostname, Info,
             maps:get(<<"hostname">>, Info, <<>>)).

%% @doc Extract plugin names from an AgentInfo map.
-spec agent_plugins(map()) -> [binary()].
agent_plugins(Info) ->
    Plugins = maps:get(plugins, Info,
                       maps:get(<<"plugins">>, Info, [])),
    [maps:get(name, P, maps:get(<<"name">>, P, <<>>)) || P <- Plugins].

%%%===================================================================
%%% Encoding helpers
%%%===================================================================

%% @doc Ensure a CommandRequest map has all required fields.
-spec encode_command_request(map()) -> map().
encode_command_request(Cmd) ->
    #{command_id => command_id(Cmd),
      plugin     => command_plugin(Cmd),
      action     => command_action(Cmd),
      parameters => maps:get(parameters, Cmd,
                             maps:get(<<"parameters">>, Cmd, #{})),
      expires_at => maps:get(expires_at, Cmd,
                             maps:get(<<"expires_at">>, Cmd, undefined))}.

%% @doc Ensure a CommandResponse map has all required fields.
-spec encode_command_response(map()) -> map().
encode_command_response(Resp) ->
    #{command_id => command_id(Resp),
      status     => response_status(Resp),
      output     => maps:get(output, Resp,
                             maps:get(<<"output">>, Resp, <<>>)),
      exit_code  => maps:get(exit_code, Resp,
                             maps:get(<<"exit_code">>, Resp, 0)),
      error      => maps:get(error, Resp,
                             maps:get(<<"error">>, Resp, undefined)),
      sent_at    => maps:get(sent_at, Resp,
                             maps:get(<<"sent_at">>, Resp, now_timestamp()))}.

%% @doc Build a SendCommandResponse message.
-spec encode_send_command_response(binary(), map()) -> map().
encode_send_command_response(AgentId, Response) ->
    #{agent_id => AgentId,
      response => encode_command_response(Response)}.

%% @doc Build an AgentEvent message.
-spec encode_agent_event(binary(), atom(), map()) -> map().
encode_agent_event(AgentId, EventType, EventData) ->
    Base = #{agent_id    => AgentId,
             occurred_at => now_timestamp()},
    case EventType of
        connected ->
            SessionId = maps:get(session_id, EventData, <<>>),
            Base#{connected => #{session_id => SessionId}};
        disconnected ->
            Reason = maps:get(reason, EventData, <<"normal">>),
            Base#{disconnected => #{reason => Reason}};
        plugin_loaded ->
            Plugin = maps:get(plugin, EventData, #{}),
            Base#{plugin_loaded => #{plugin => Plugin}}
    end.
