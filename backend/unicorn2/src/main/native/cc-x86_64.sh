#!/bin/sh
# unicorn's CMakeLists and qemu/configure probe the host by running the bare compiler
# (no CMAKE_OSX_ARCHITECTURES), so on Apple Silicon they would pick the aarch64 TCG backend
# for the x86_64 build. This compiler targets x86_64 on its own.
exec xcrun -sdk macosx clang -arch x86_64 "$@"
