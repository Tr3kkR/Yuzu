# Yuzu

A multi-platform agent and server framework for real-time endpoint management. Yuzu is the successor to 1e Tachyon, built from the ground up in C++23 with a focus on extensibility, performance, and cross-platform portability.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Yuzu Server                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Gateway   │  │  Agent Mgr   │  │   Plugin Host     │  │
│  │  (gRPC/TLS) │  │  (Sessions)  │  │  (Server Plugins) │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
              │ gRPC (Protobuf / TLS)
┌─────────────────────────────────────────────────────────────┐
│                    Yuzu Agent (per endpoint)                 │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Comms     │  │  Plugin Mgr  │  │  Platform Adapter │  │
│  │  (gRPC)     │  │  (.so/.dll)  │  │  Win/Lin/mac/ARM  │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Concern | Choice | Rationale |
|---|---|---|
| Language | C++23 | `std::expected`, ranges, modules (where available) |
| Build | CMake 3.28+ + Meson 1.3+ | CMake for broad IDE support; Meson for fast, clean builds |
| Transport | gRPC + Protobuf | Bidirectional streaming, strongly typed, TLS built-in |
| Deps | vcpkg (manifest mode) | Reproducible, cross-platform, CMake/Meson integration |
| Plugin ABI | C stable ABI | Language-agnostic, binary-stable, dlopen/.dll safe |
| Platforms | Windows, Linux, macOS, ARM | Enterprise + embedded coverage |

## Project Layout

```
Yuzu/
├── agents/core/          # Agent daemon (connects to server, loads plugins)
├── server/core/          # Server daemon (manages agent sessions)
├── server/gateway/       # gRPC gateway / TLS termination
├── sdk/                  # Public SDK: plugin ABI headers + C++ wrappers
├── proto/                # Protobuf definitions (source of truth for the wire protocol)
├── cmake/                # CMake modules and cross-compilation toolchains
├── tools/                # Developer scripts (codegen, linting, packaging)
├── tests/                # Unit and integration tests
└── .github/workflows/    # CI for Windows / Linux / macOS / ARM
```

## Building

### Prerequisites

- CMake ≥ 3.28 or Meson ≥ 1.3
- A C++23-capable compiler:
  - MSVC 19.38+ (VS 2022 17.8+)
  - GCC 13+
  - Clang 17+
- [vcpkg](https://github.com/microsoft/vcpkg) (or set `VCPKG_ROOT`)

### With CMake

```bash
cmake --preset linux-debug       # or windows-debug, macos-debug, arm64-debug
cmake --build --preset linux-debug
```

### With Meson

```bash
meson setup builddir -Dbuildtype=debug
meson compile -C builddir
```

### CMake Presets

| Preset | Platform | Compiler | Config |
|---|---|---|---|
| `linux-debug` | Linux x64 | GCC/Clang | Debug |
| `linux-release` | Linux x64 | GCC/Clang | Release |
| `windows-debug` | Windows x64 | MSVC | Debug |
| `windows-release` | Windows x64 | MSVC | Release |
| `macos-debug` | macOS (Apple Silicon / x64) | Apple Clang | Debug |
| `macos-release` | macOS | Apple Clang | Release |
| `arm64-linux-debug` | Linux ARM64 | aarch64-gcc | Debug (cross) |

## Writing a Plugin

Plugins are in-process shared libraries (`.dll` / `.so`) that export a single C-ABI descriptor function. See [`sdk/include/yuzu/plugin.h`](sdk/include/yuzu/plugin.h) and the example plugin in [`agents/plugins/example/`](agents/plugins/example/).

```cpp
#include <yuzu/plugin.hpp>

class MyPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "my-plugin"; }
    // ...
};

YUZU_PLUGIN_EXPORT(MyPlugin)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
