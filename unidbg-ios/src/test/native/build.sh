#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -o kqueue kqueue.c -m64 -arch arm64 -miphoneos-version-min=7.1 && \
mv kqueue ../resources/example_binaries/
xcrun -sdk macosx clang -o ../resources/example_binaries/cpu_features -m64 cpu_features.c
xcrun -sdk iphoneos clang -o ../resources/example_binaries/ios_cpu_features -m64 -arch arm64 cpu_features.c
