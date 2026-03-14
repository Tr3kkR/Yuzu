# Convenience targets wrapping CMake presets.
# Usage: make configure && make build && make test

.PHONY: configure build test clean

PRESET ?= linux-debug

configure:
	cmake --preset $(PRESET)

build:
	cmake --build --preset $(PRESET)

test:
	ctest --preset $(PRESET)

clean:
	rm -rf build/
