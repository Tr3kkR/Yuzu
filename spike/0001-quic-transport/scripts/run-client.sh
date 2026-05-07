#!/usr/bin/env bash
# Run the quicer client via `erl` with the right paths, since escripts
# can't load NIFs (libquicer_nif.so lives in quicer/priv/, not the bundle).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$HERE/erlang-client/_build/default/lib"

# Build a `-pa` argument list covering every dep's ebin dir.
PA_ARGS=()
for app in "$LIB"/*/ebin; do
    PA_ARGS+=(-pa "$app")
done

# Build an Erlang-syntax list of args. We escape only " and \, which is
# enough for our flag/value pairs (paths, mode names).
args_term="["
first=1
for a in "$@"; do
    esc="${a//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    if [[ $first -eq 1 ]]; then
        args_term+="\"$esc\""
        first=0
    else
        args_term+=", \"$esc\""
    fi
done
args_term+="]"

exec erl +sbtu +A1 -noshell \
    "${PA_ARGS[@]}" \
    -eval "yuzu_quic_spike_client:main(${args_term})." \
    -eval "init:stop()."
