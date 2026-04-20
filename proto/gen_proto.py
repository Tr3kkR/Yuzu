import subprocess, sys, os, glob, shutil, re

outdir = sys.argv[1]
protoc = sys.argv[2]
plugin = sys.argv[3]
proto_root = sys.argv[4]
protos = sys.argv[5:]

# Validate protoc version for reproducible codegen
_ver_result = subprocess.run([protoc, '--version'], capture_output=True, text=True)
if _ver_result.returncode != 0:
    print("ERROR: protoc --version failed", file=sys.stderr)
    sys.exit(1)
_ver_str = _ver_result.stdout.strip()  # e.g. "libprotoc 27.3"
print(f"gen_proto.py: using {_ver_str}")

# Extract major version and enforce minimum (protobuf 3.15+ or 4.x/5.x/27.x)
_m = re.search(r'(\d+)\.(\d+)', _ver_str)
if _m:
    _major = int(_m.group(1))
    if _major < 3:
        print(f"ERROR: protoc version too old: {_ver_str} (need >= 3.15)", file=sys.stderr)
        sys.exit(1)

for proto in protos:
    r = subprocess.run([
        protoc,
        "--cpp_out=" + outdir,
        "--grpc_out=" + outdir,
        "--plugin=protoc-gen-grpc=" + plugin,
        "-I", proto_root,
        proto
    ], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(r.returncode)

for f in glob.glob(outdir + "/**/*.pb.*", recursive=True):
    try:
        with open(f, "r", encoding="utf-8") as fh:
            content = fh.read()
        # Flatten Yuzu proto include paths so generated files can reference
        # sibling Yuzu protos by basename alone (matching the flattened layout
        # produced by the shutil.move step below).
        #
        # SCOPE: yuzu/... only. Well-known types like google/protobuf/*.pb.h
        # MUST retain their canonical include path because they resolve via
        # vcpkg's protobuf include root, not our build-tree proto/ directory.
        # A broader pattern (e.g. "any subdir") would rewrite
        # `#include "google/protobuf/timestamp.pb.h"` to `"timestamp.pb.h"`,
        # which doesn't exist anywhere and breaks every C++ build target.
        content = re.sub(
            r'#include "yuzu/(?:[^"/]+/)*([^"/]+\.pb\.h)"',
            r'#include "\1"',
            content,
        )
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(content)
    except UnicodeDecodeError:
        pass

for f in glob.glob(outdir + "/**/*.pb.*", recursive=True):
    dest = os.path.join(outdir, os.path.basename(f))
    if f != dest:
        shutil.move(f, dest)

for dirpath, dirnames, filenames in os.walk(outdir, topdown=False):
    if dirpath != outdir:
        try:
            os.rmdir(dirpath)
        except OSError:
            pass