# ClusterFuzzLite builder image. base-builder ships the instrumented clang
# toolchain + $LIB_FUZZING_ENGINE; build.sh compiles the harnesses directly
# (no meson/vcpkg inside this container — the targets are deliberately
# closure-light, see .clusterfuzzlite/README.md).
FROM gcr.io/oss-fuzz-base/base-builder@sha256:7e051ff2f22c7ab9bd4714427ad92165b216436b8477579ec8fb92ed65a9c8c3

# nlohmann/json (header-only) for the guardian_rule_spec target — pinned tag,
# matches the major.minor line vcpkg resolves for the server build.
RUN git clone --depth 1 --branch v3.12.0 https://github.com/nlohmann/json.git "$SRC/nlohmann_json"

# $SRC/Yuzu — EXACT repo-name case. ClusterFuzzLite bind-mounts the PR
# checkout at $SRC/<github-repo-name> ("Yuzu"), shadowing this COPY; a
# lowercase path here leaves the container building the image-time copy
# instead of the PR (first run failed exactly that way — "no such file
# /src/yuzu/tests/fuzz/...").
COPY . "$SRC/Yuzu"
COPY .clusterfuzzlite/build.sh "$SRC/build.sh"
WORKDIR "$SRC/Yuzu"
