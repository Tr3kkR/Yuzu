%%% Throwaway quicer client for #376 PR 0 spike.
%%%
%%% Modes (selected by --mode):
%%%   handshake    — connect, log handshake info, close
%%%   bidi-30s     — 30 s of 1 KiB writes both directions, echo verified
%%%   halfclose    — 5 s of writes, then half-close, time how long until
%%%                  server's half-close arrives back at us (must be < 1 s)
%%%   slow-reader  — same as bidi-30s but server is in slow-reader mode;
%%%                  we expect a flow-controlled stall and clean resume
%%%
%%% Output: per-line millisecond timestamps to stderr; final stats as a
%%% single JSON object on stdout (consumed by run-all.sh).
-module(yuzu_quic_spike_client).
-include_lib("quicer/include/quicer.hrl").

-export([main/1]).

-define(HOST, "localhost").
-define(PORT, 50053).
-define(ALPN, "yuzu-spike").
-define(CHUNK_SIZE, 1024).
-define(SEND_INTERVAL_US, 1000).      %% pacing inside the sender process (~1 MiB/s)

%% =========================================================================

main(Args) ->
    {ok, _} = application:ensure_all_started(quicer),
    {Mode, CaCert} = parse_args(Args),
    log("client starting mode=~s cacert=~s", [Mode, CaCert]),
    Result =
        try run(Mode, CaCert)
        catch
            throw:{fail, R} ->
                log("FAIL: ~p", [R]),
                #{ok => false, reason => format_term(R)};
            Class:Reason:Stack ->
                log("CRASH: ~p:~p ~p", [Class, Reason, Stack]),
                #{ok => false, reason => format_term({Class, Reason})}
        end,
    emit_json(Mode, Result),
    case maps:get(ok, Result, false) of
        true  -> erlang:halt(0);
        false -> erlang:halt(3)
    end.

parse_args(Args) ->
    Map = parse(Args, #{}),
    Mode = maps:get(mode, Map, "bidi-30s"),
    Ca   = maps:get(cacert, Map, "../certs/ca.crt"),
    {Mode, Ca}.

parse([], Acc) -> Acc;
parse(["--mode", V | Rest], Acc) -> parse(Rest, Acc#{mode => V});
parse(["--cacert", V | Rest], Acc) -> parse(Rest, Acc#{cacert => V});
parse([Other | _], _) -> throw({fail, {bad_arg, Other}}).

%% =========================================================================
%% Scenario runners
%% =========================================================================

run("handshake", CaCert) ->
    T0 = ms(),
    Conn = connect(CaCert),
    T1 = ms(),
    Alpn = case quicer:getopt(Conn, alpn) of
               {ok, A}    -> A;
               _          -> undefined
           end,
    log("connected handshake_ms=~p alpn=~p", [T1 - T0, Alpn]),
    quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, 1000),
    #{ok => true, handshake_ms => T1 - T0, alpn => format_term(Alpn)};

run("bidi-30s", CaCert) ->
    bidi(CaCert, 30000, "bidi");

run("slow-reader", CaCert) ->
    bidi(CaCert, 30000, "slow-reader");

run("halfclose", CaCert) ->
    Conn = connect(CaCert),
    Stream = open_stream(Conn),
    Self = self(),
    SenderPid = spawn_link(fun() -> sender_loop(Self, Stream, ms() + 5000, 0) end),
    State0 = init_state(Stream, ms() + 6000),
    %% Drain receives + wait for sender to report done.
    State1 = drive(State0#{sender => SenderPid}, fun phase_wait_for_sender/1),
    SentClose = ms(),
    log("halfclose: client issuing FIN at ~p", [SentClose]),
    ok = case quicer:async_send(Stream, <<>>, ?QUIC_SEND_FLAG_FIN) of
             {ok, _} -> ok;
             ok      -> ok;
             E       -> throw({fail, {fin_send, E}})
         end,
    State2 = drive(State1#{deadline => ms() + 5000,
                           halfclose_sent_ms => SentClose,
                           awaiting_peer_fin => true},
                   fun wait_peer_fin/1),
    quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, 1000),
    Lag = case maps:get(peer_fin_ms, State2, undefined) of
              undefined -> infinity;
              T         -> T - SentClose
          end,
    Ok = is_integer(Lag) andalso Lag =< 1000,
    #{
        ok => Ok,
        halfclose_lag_ms => Lag,
        sent_chunks => maps:get(sent_chunks, State2, 0),
        recv_chunks => maps:get(recv_chunks, State2, 0),
        sent_bytes => maps:get(sent_bytes, State2, 0),
        recv_bytes => maps:get(recv_bytes, State2, 0)
    }.

bidi(CaCert, DurationMs, Tag) ->
    Conn = connect(CaCert),
    Stream = open_stream(Conn),
    log("~s mode: streaming for ~p ms", [Tag, DurationMs]),
    Self = self(),
    SenderEnd = ms() + DurationMs,
    SenderPid = spawn_link(fun() -> sender_loop(Self, Stream, SenderEnd, 0) end),
    State0 = init_state(Stream, SenderEnd + 1000),
    State1 = drive(State0#{sender => SenderPid}, fun phase_wait_for_sender/1),
    LastSent = maps:get(sent_chunks, State1, 0),
    log("~s: send phase done sent_chunks=~p sent_bytes=~p; FIN-ing",
        [Tag, LastSent, maps:get(sent_bytes, State1)]),
    SentClose = ms(),
    case quicer:async_send(Stream, <<>>, ?QUIC_SEND_FLAG_FIN) of
        {ok, _} -> ok;
        ok      -> ok;
        FE      -> throw({fail, {fin_send, FE}})
    end,
    State2 = drive(State1#{deadline => ms() + 30000,
                           awaiting_peer_fin => true,
                           halfclose_sent_ms => SentClose},
                   fun phase_drain/1),
    quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, 1000),
    Sent = maps:get(sent_bytes, State2, 0),
    Recv = maps:get(recv_bytes, State2, 0),
    NextSeq = maps:get(next_seq, State2, 0),
    Loss = Sent - Recv,
    FinSeen = maps:get(peer_fin_ms, State2, undefined) =/= undefined,
    Ok = (Loss =:= 0) andalso (NextSeq =:= LastSent) andalso FinSeen,
    Lag = case {maps:get(peer_fin_ms, State2, undefined), SentClose} of
              {undefined, _} -> infinity;
              {T, S}         -> T - S
          end,
    #{
        ok => Ok,
        mode => Tag,
        sent_chunks => LastSent,
        sent_bytes => Sent,
        recv_chunks => maps:get(recv_chunks, State2, 0),
        recv_bytes => Recv,
        loss_bytes => Loss,
        next_expected_seq => NextSeq,
        peer_fin_lag_ms => Lag,
        peer_fin_observed => FinSeen
    }.

%% =========================================================================
%% State + driver
%% =========================================================================

init_state(Stream, DeadlineMs) ->
    #{
        stream => Stream,
        deadline => DeadlineMs,
        sender => undefined,
        sender_done => false,
        sent_chunks => 0,           %% updated when sender reports
        sent_bytes => 0,
        recv_chunks => 0,
        recv_bytes => 0,
        next_seq => 0,
        partial => <<>>,
        awaiting_peer_fin => false,
        peer_fin_ms => undefined,
        halfclose_sent_ms => undefined
    }.

%% =========================================================================
%% Sender process — drives quicer:send/2 (sync) on ms-paced cadence until
%% EndAtMs. Sync send delivers send_complete to the *calling* process, so
%% send_complete events stay in the sender's mailbox and don't pollute the
%% main proc's receive loop. Sync semantics also mean the byte count is
%% authoritative — every counted send is on the wire.
%% =========================================================================

sender_loop(Reporter, Stream, EndAtMs, Seq) ->
    Now = ms(),
    case Now >= EndAtMs of
        true ->
            Reporter ! {sender_done, self(), Seq, Seq * ?CHUNK_SIZE};
        false ->
            Payload = make_chunk(Seq),
            case quicer:send(Stream, Payload) of
                {ok, _} ->
                    %% 1 ms pacing → ~1 MiB/s → ~30 MiB across the 30 s
                    %% bidi/slow-reader windows. Predictable and well below
                    %% any QUIC flow-control limit.
                    timer:sleep(1),
                    sender_loop(Reporter, Stream, EndAtMs, Seq + 1);
                {error, cancelled} ->
                    log_sender("send cancelled at seq ~p", [Seq]),
                    Reporter ! {sender_done, self(), Seq, Seq * ?CHUNK_SIZE};
                {error, Reason} ->
                    log_sender("send error ~p at seq ~p", [Reason, Seq]),
                    %% Could be transient flow-control. Retry once with backoff.
                    timer:sleep(20),
                    case quicer:send(Stream, Payload) of
                        {ok, _} -> sender_loop(Reporter, Stream, EndAtMs, Seq + 1);
                        Other   ->
                            log_sender("retry failed ~p", [Other]),
                            Reporter ! {sender_done, self(), Seq, Seq * ?CHUNK_SIZE}
                    end;
                {error, Reason, Sub} ->
                    log_sender("send error ~p:~p at seq ~p", [Reason, Sub, Seq]),
                    Reporter ! {sender_done, self(), Seq, Seq * ?CHUNK_SIZE}
            end
    end.

log_sender(Fmt, Args) ->
    io:format(standard_error, "[~p ms] [sender] " ++ Fmt ++ "~n", [ms() | Args]).

make_chunk(Seq) ->
    Seed = Seq band 16#FFFFFFFF,
    <<Seed:32/big, 0:8160>>.    %% 4 + 1020 = 1024 bytes

%% Driver loop: receive one quic event, transition state via Stop fun.
%% Stop fun returns either {continue, State} or {stop, State}.
drive(State, StopFun) ->
    case StopFun(State) of
        {stop, S}         -> S;
        {continue, S}     -> drive(handle_one_event(S), StopFun);
        {continue_now, S} -> drive(S, StopFun)
    end.

%% Stop conditions for each phase.

phase_wait_for_sender(State) ->
    case maps:get(sender_done, State, false) of
        true  -> {stop, State};
        false ->
            case ms() >= maps:get(deadline, State) of
                true  ->
                    log("phase_wait_for_sender: deadline before sender exit"),
                    {stop, State};
                false ->
                    {continue, State}
            end
    end.

phase_drain(State) ->
    case maps:get(awaiting_peer_fin, State, false) of
        true ->
            case ms() >= maps:get(deadline, State) of
                true  ->
                    log("phase_drain deadline reached without peer FIN"),
                    {stop, State};
                false ->
                    {continue, State}
            end;
        false ->
            {stop, State}
    end.

wait_peer_fin(State) ->
    case maps:get(peer_fin_ms, State, undefined) of
        undefined ->
            case ms() >= maps:get(deadline, State) of
                true  -> {stop, State};
                false -> {continue, State}
            end;
        _ -> {stop, State}
    end.

%% Block on the mailbox for one quic event (or sender_done) and update state.
handle_one_event(State) ->
    Stream = maps:get(stream, State),
    Sender = maps:get(sender, State, undefined),
    Now = ms(),
    Deadline = maps:get(deadline, State),
    Timeout = max(0, min(100, Deadline - Now)),
    receive
        {quic, Bin, Stream, _Props} when is_binary(Bin) ->
            consume_into(State, Bin);
        {quic, peer_send_shutdown, Stream, _} ->
            log("event: peer_send_shutdown"),
            State#{peer_fin_ms => ms(), awaiting_peer_fin => false};
        {quic, peer_send_aborted, Stream, ErrCode} ->
            log("event: peer_send_aborted err=~p", [ErrCode]),
            State#{peer_fin_ms => ms(), awaiting_peer_fin => false};
        {quic, send_complete, Stream, _IsCancelled} ->
            State;
        {quic, stream_closed, Stream, _Props} ->
            log("event: stream_closed"),
            State#{peer_fin_ms => maps:get(peer_fin_ms, State, ms()),
                   awaiting_peer_fin => false};
        {quic, transport_shutdown, _Conn, Reason} ->
            log("event: transport_shutdown ~p", [Reason]),
            State;
        {quic, shutdown, _Conn, _Prop} ->
            log("event: connection shutdown"),
            State;
        {sender_done, Sender, LastSeq, BytesSent} ->
            log("sender exited last_seq=~p bytes=~p", [LastSeq, BytesSent]),
            State#{sender_done => true,
                   sent_chunks => LastSeq,
                   sent_bytes => BytesSent};
        {'EXIT', Sender, Reason} ->
            log("sender ~p exited with reason ~p", [Sender, Reason]),
            State#{sender_done => true};
        {quic, _Tag, _, _} = Other ->
            log("event: ignoring ~p", [element(2, Other)]),
            State;
        Other ->
            log("event: unexpected ~p", [Other]),
            State
    after Timeout ->
        State
    end.

%% Append Bin to partial, peel off whole 1 KiB chunks, validate seq, update counters.
consume_into(State, Bin) ->
    Buf = <<(maps:get(partial, State))/binary, Bin/binary>>,
    consume_loop(State, Buf).

consume_loop(State, <<Chunk:?CHUNK_SIZE/binary, Rest/binary>>) ->
    <<Seq:32/big, _/binary>> = Chunk,
    Expected = maps:get(next_seq, State),
    case Seq =:= (Expected band 16#FFFFFFFF) of
        true ->
            consume_loop(State#{
                next_seq := Expected + 1,
                recv_chunks := maps:get(recv_chunks, State) + 1,
                recv_bytes := maps:get(recv_bytes, State) + ?CHUNK_SIZE
            }, Rest);
        false ->
            log("seq mismatch: expected ~p got ~p", [Expected, Seq]),
            throw({fail, {seq_mismatch, Expected, Seq}})
    end;
consume_loop(State, Tail) ->
    State#{partial := Tail}.

%% =========================================================================
%% Connection / stream helpers
%% =========================================================================

connect(CaCert) ->
    Opts = #{
        verify => verify_peer,
        cacertfile => CaCert,
        alpn => [?ALPN],
        peer_unidi_stream_count => 0,
        peer_bidi_stream_count => 4,
        idle_timeout_ms => 60000,
        handshake_idle_timeout_ms => 5000,
        %% Make the receive-side stream window generous so the slow-reader
        %% scenario hits *server* backpressure, not client recv buffer.
        stream_recv_window_default => 1048576
    },
    case quicer:connect(?HOST, ?PORT, Opts, 5000) of
        {ok, Conn} -> Conn;
        {ok, Conn, _Cert} -> Conn;
        {error, R} -> throw({fail, {connect, R}});
        {error, R, S} -> throw({fail, {connect, R, S}})
    end.

open_stream(Conn) ->
    Opts = #{
        active => true,
        open_flag => ?QUIC_STREAM_OPEN_FLAG_NONE,
        start_flag => ?QUIC_STREAM_START_FLAG_IMMEDIATE
    },
    case quicer:start_stream(Conn, Opts) of
        {ok, S}        -> S;
        {error, R}     -> throw({fail, {start_stream, R}});
        {error, R, S}  -> throw({fail, {start_stream, R, S}})
    end.

%% =========================================================================
%% Misc
%% =========================================================================

ms() -> erlang:monotonic_time(millisecond).

log(Fmt) -> log(Fmt, []).
log(Fmt, Args) ->
    io:format(standard_error, "[~p ms] [client] " ++ Fmt ++ "~n", [ms() | Args]).

format_term(T) ->
    iolist_to_binary(io_lib:format("~p", [T])).

emit_json(Mode, Map) ->
    Pairs = [{<<"role">>, <<"client">>}, {<<"mode">>, list_to_binary(Mode)} |
             [ {atom_to_binary(K, utf8), V} || {K, V} <- maps:to_list(Map),
                                              K =/= mode, K =/= stream,
                                              K =/= partial ]],
    Body = string:join([encode_pair(K, V) || {K, V} <- Pairs], ","),
    io:format("{~s}~n", [Body]).

encode_pair(K, V) ->
    [$", binary_to_list(K), $", $:, encode_val(V)].

encode_val(true)                 -> "true";
encode_val(false)                -> "false";
encode_val(infinity)             -> [$", "infinity", $"];
encode_val(undefined)            -> "null";
encode_val(V) when is_integer(V) -> integer_to_list(V);
encode_val(V) when is_atom(V)    -> [$", atom_to_list(V), $"];
encode_val(V) when is_binary(V)  -> [$", escape(binary_to_list(V)), $"];
encode_val(V)                    -> [$", io_lib:format("~p", [V]), $"].

escape(S) -> [escape_char(C) || C <- S].
escape_char($")  -> "\\\"";
escape_char($\\) -> "\\\\";
escape_char($\n) -> "\\n";
escape_char($\r) -> "\\r";
escape_char($\t) -> "\\t";
escape_char(C)   -> C.
