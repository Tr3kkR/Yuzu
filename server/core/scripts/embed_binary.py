#!/usr/bin/env python3
"""Embed an arbitrary binary file as a C++ byte array.

Used for woff2 fonts and other small binaries the server must serve at
runtime without an external file dependency. Output is a .cpp file with
``extern const std::string_view k<Symbol>;`` backed by a constexpr
``unsigned char`` array.

Usage:
    embed_binary.py <input.bin> <output.cpp> <symbol_name>
"""

import sys
from pathlib import Path

BYTES_PER_LINE = 16


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: embed_binary.py <input.bin> <output.cpp> <symbol_name>",
              file=sys.stderr)
        return 1
    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    symbol = sys.argv[3]

    data = in_path.read_bytes()

    out = bytearray()
    out += f"// AUTO-GENERATED from {in_path.name} by embed_binary.py — do not edit.\n".encode("utf-8")
    out += f"// Source: {len(data):,} bytes.\n\n".encode("ascii")
    out += b"#include <cstddef>\n#include <string_view>\n\n"
    out += b"namespace yuzu::server {\nnamespace {\n"
    out += f"constexpr unsigned char k{symbol}Bytes[] = {{\n".encode("ascii")
    for i in range(0, len(data), BYTES_PER_LINE):
        chunk = data[i:i + BYTES_PER_LINE]
        out += b"    "
        out += b", ".join(f"0x{b:02x}".encode("ascii") for b in chunk)
        out += b",\n"
    out += b"};\n}  // namespace\n\n"
    # string_view of the byte data — content is binary, not text, but
    # std::string_view of <char,N> is the cheapest way to feed it to
    # httplib::set_content without copying the full font into a std::string.
    out += (f"extern const std::string_view k{symbol} = std::string_view("
            f"reinterpret_cast<const char*>(k{symbol}Bytes), "
            f"sizeof(k{symbol}Bytes));\n").encode("ascii")
    out += b"}  // namespace yuzu::server\n"

    out_path.write_bytes(bytes(out))
    print(f"embed_binary.py: wrote {out_path} "
          f"({len(data):,} bytes -> {(len(data) + BYTES_PER_LINE - 1) // BYTES_PER_LINE} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
