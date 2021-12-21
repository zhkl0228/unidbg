#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -o kqueue kqueue.c -m32 -arch armv7 -miphoneos-version-min=7.1 && \
mv kqueue kqueue32 && \
xcrun -sdk iphoneos clang -o kqueue kqueue.c -m64 -arch arm64 -miphoneos-version-min=7.1 && \
mv kqueue kqueue64 && \
lipo -create kqueue32 kqueue64 -output kqueue && \
rm kqueue32 kqueue64 && \
mv kqueue ../resources/example_binaries/
