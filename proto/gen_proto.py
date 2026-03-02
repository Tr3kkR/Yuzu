import subprocess, sys, os, glob, shutil, re

outdir = sys.argv[1]
protoc = sys.argv[2]
plugin = sys.argv[3]
proto_root = sys.argv[4]
protos = sys.argv[5:]

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
        content = re.sub(r'#include "(?:[^"/]+/)*([^"/]+\.pb\.h)"', r'#include "\1"', content)
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