# Contributing to Yuzu

## Getting Started

1. **Prerequisites**: CMake 3.28+, Ninja, a C++23 compiler, and vcpkg. See [CLAUDE.md](CLAUDE.md) for full build instructions.
2. **Clone and build**:
   ```bash
   git clone https://github.com/Tr3kkR/Yuzu.git && cd Yuzu
   cmake --preset linux-debug
   cmake --build --preset linux-debug
   ctest --preset linux-debug
   ```
   Or use `make configure && make build && make test` on Linux.

## Branch Naming

- `feature/<short-description>` for new functionality
- `fix/<short-description>` for bug fixes

Branch from `main`. Keep branches focused on a single change.

## Pull Request Process

1. Ensure CI passes (builds on Linux, Windows, macOS, ARM64)
2. Run `clang-tidy` locally against changed files (the repo `.clang-tidy` config is picked up automatically)
3. Write a clear PR title and description using the PR template
4. Keep PRs small where possible; large features should be broken into incremental PRs

## Coding Standards

The project follows C++23 conventions enforced by `.clang-tidy`:

- **Naming**: PascalCase classes, snake_case functions/variables, `k`-prefix constants, trailing `_` for private members
- **Error handling**: Use `std::expected<T, E>` — no exceptions in core code
- **Includes**: `#pragma once`, ordered STL -> third-party -> project
- **Strings**: Prefer `std::string_view` for parameters, `std::format` for formatting
- **Memory**: No raw `new`/`delete`; use smart pointers and RAII

See [CLAUDE.md](CLAUDE.md) for the complete coding conventions.

## Writing Plugins

Plugins use a stable C ABI (`sdk/include/yuzu/plugin.h`) with a C++ wrapper (`sdk/include/yuzu/plugin.hpp`).

1. Copy `agents/plugins/example/` as a starting point
2. Implement your plugin class using the `YUZU_PLUGIN_EXPORT` macro
3. Add a `CMakeLists.txt` that links against `yuzu::sdk`
4. Register your plugin directory in the root `CMakeLists.txt`

See the existing plugins (`chargen`, `status`, `device_identity`) for patterns.

## Running Tests

```bash
cmake --preset linux-debug          # configure with tests enabled
cmake --build --preset linux-debug  # build
ctest --preset linux-debug          # run tests
```

Tests use [Catch2](https://github.com/catchorg/Catch2) and live in `tests/unit/`.
