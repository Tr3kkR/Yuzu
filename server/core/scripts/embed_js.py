#!/usr/bin/env python3
"""Embed a JavaScript file as a C++ string constant.

Reads an input .js file and writes a .cpp file declaring an
``extern const std::string`` whose runtime value is byte-identical
to the input. Used at build time to bundle vendored JS libraries
(htmx, ECharts, ...) into the server binary so the dashboard works
in air-gapped deployments.

MSVC enforces a 16,380-byte limit on raw string literals (C2026), so
the input is sliced into ~14,000-byte chunks held as ``const char*``
fragments and concatenated at static-init time. The same approach is
used by hand for htmx in static_js_bundle.cpp; this script automates
it for files large enough that hand-chunking would be tedious.

The output .cpp is written in BINARY mode so input bytes pass through
verbatim. C++ raw string literals capture source bytes 1:1 regardless
of source-file encoding, which means a JS file containing UTF-8 (e.g.
a copyright header with curly quotes or an em-dash) round-trips
losslessly. Writing the .cpp as Python text would expand input bytes
0x80-0xFF as 2-byte UTF-8 sequences and silently corrupt the bundle.

Usage:
    embed_js.py <input.js> <output.cpp> <symbol_name>
"""

import sys
from pathlib import Path

CHUNK_SIZE = 14_000  # bytes; comfortably under MSVC's 16,380 limit
DELIM = b"ECHARTSEMBED"  # raw-string delimiter — must not appear in input


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: embed_js.py <input.js> <output.cpp> <symbol_name>",
              file=sys.stderr)
        return 1
    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    symbol = sys.argv[3].encode("ascii")

    data = in_path.read_bytes()
    if (b")" + DELIM + b'"') in data:
        print(f"ERROR: input contains the raw-string close delimiter "
              f"')%s\"' — pick a different DELIM" % DELIM.decode(),
              file=sys.stderr)
        return 1

    chunks = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]

    out = bytearray()
    out += f"// AUTO-GENERATED from {in_path.name} by embed_js.py — do not edit.\n".encode("utf-8")
    out += f"// Source: {len(data):,} bytes, {len(chunks)} chunks of <= {CHUNK_SIZE} bytes.\n".encode("ascii")
    out += b"\n#include <string>\n\n"
    out += b"// NOLINTBEGIN(cert-err58-cpp)\nnamespace {\n"

    for i, chunk in enumerate(chunks, start=1):
        out += b"const char* const k" + symbol
        out += f"Part{i}".encode("ascii")
        out += b' = R"' + DELIM + b"("
        out += chunk
        out += b")" + DELIM + b'";\n'

    out += b"}  // namespace\n\nnamespace yuzu::server {\n"
    out += b"extern const std::string k" + symbol + b" = "
    if len(chunks) > 1:
        parts = b" + ".join(
            b"std::string(k" + symbol + f"Part{i}".encode("ascii") + b")"
            for i in range(1, len(chunks) + 1)
        )
    else:
        parts = b"std::string(k" + symbol + b"Part1)"
    out += parts + b";\n"
    out += b"}  // namespace yuzu::server\n"
    out += b"// NOLINTEND(cert-err58-cpp)\n"

    out_path.write_bytes(bytes(out))
    print(f"embed_js.py: wrote {out_path} "
          f"({len(data):,} bytes -> {len(chunks)} chunks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
