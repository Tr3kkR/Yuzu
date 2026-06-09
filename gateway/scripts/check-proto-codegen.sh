#!/usr/bin/env bash
#
# check-proto-codegen.sh — F-3 (#1243): fail if the committed gateway protobuf
# modules (apps/yuzu_gw/src/*_pb.erl) have drifted from priv/proto.
#
# Why this exists: the gateway carries its OWN gpb-generated copies of the proto
# modules (separate from the server's protoc output). gpb modules are
# self-contained — if a field is added to a .proto but a module is not
# regenerated, the gateway silently stops carrying that field across transit
# (this is exactly the per-agent-enrollment CSR field-drop bug PR5 fixed). This
# guard converts that silent drift into a hard CI failure.
#
# How: regenerate every top-level proto with the EXACT gpb_opts read from
# rebar.config (via file:consult, so the guard cannot drift from the build's own
# options) into a temp dir, then byte-diff against the committed modules. gpb is
# version-pinned in rebar.config (4.21.7) + target_erlang_version is fixed, so
# the output is deterministic and reproducible across machines.
#
# Prereq: `rebar3 compile` (or any rebar3 run that fetches deps) must have
# populated _build so gpb's ebin is available. CI runs this right after the
# gateway compile step.
#
# Usage: bash scripts/check-proto-codegen.sh   (from the gateway/ dir or anywhere)
set -euo pipefail

# Resolve to the gateway root regardless of CWD.
cd "$(dirname "$0")/.."

SRC="apps/yuzu_gw/src"
PROTO_DIR="priv/proto"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ ! -d "$PROTO_DIR" ]; then
    echo "ERROR: $PROTO_DIR not found — run from the gateway project root." >&2
    exit 2
fi

GPB_EBIN="$(find _build -path '*/gpb/ebin' -type d 2>/dev/null | head -1)"
if [ -z "$GPB_EBIN" ]; then
    echo "ERROR: gpb ebin not found under _build/. Run 'rebar3 compile' first." >&2
    exit 2
fi

# Regenerate every TOP-LEVEL proto (the package-pathed copies under
# priv/proto/yuzu/<pkg>/v1/ are import targets, not compiled directly — they
# share basenames with the top-level files and would collide on module name).
erl -noshell -pa "$GPB_EBIN" -eval "
    {ok, Terms} = file:consult(\"rebar.config\"),
    Grpc = proplists:get_value(grpc, Terms, []),
    GpbOpts = proplists:get_value(gpb_opts, Grpc, []),
    Opts = GpbOpts ++ [{i, \"$PROTO_DIR\"}, {o_erl, \"$TMP\"}, {o_hrl, \"$TMP\"}],
    Protos = filelib:wildcard(\"$PROTO_DIR/*.proto\"),
    case Protos of
        [] -> io:format(standard_error, \"no top-level protos in $PROTO_DIR~n\", []), halt(3);
        _  -> ok
    end,
    lists:foreach(fun(P) ->
        Base = filename:basename(P),
        case gpb_compile:file(Base, Opts) of
            ok -> ok;
            Err ->
                io:format(standard_error, \"gpb_compile ~s failed: ~p~n\", [Base, Err]),
                halt(3)
        end
    end, Protos),
    halt(0).
" || { echo "ERROR: proto regeneration failed (see above)." >&2; exit 3; }

drift=0
for regen in "$TMP"/*_pb.erl; do
    [ -e "$regen" ] || continue
    name="$(basename "$regen")"
    committed="$SRC/$name"
    if [ ! -f "$committed" ]; then
        echo "::error::regenerated $name has no committed counterpart in $SRC" >&2
        drift=1
        continue
    fi
    if ! diff -u "$committed" "$regen"; then
        echo "::error::gateway proto codegen drift in $name" >&2
        drift=1
    fi
done

if [ "$drift" -ne 0 ]; then
    echo "" >&2
    echo "Committed gateway _pb.erl differ from priv/proto. Regenerate and commit:" >&2
    echo "    cd gateway && rebar3 grpc gen   # or the gpb regen used to author them" >&2
    echo "(gpb is version-pinned in rebar.config, so a matching toolchain reproduces these exactly.)" >&2
    exit 1
fi

echo "OK: all gateway _pb.erl match priv/proto."
